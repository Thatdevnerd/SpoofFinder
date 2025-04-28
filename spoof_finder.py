from asyncio import new_event_loop, gather
from datetime import datetime
from re import compile
from typing import Optional, List, Dict, Union, Tuple
from aioconsole import ainput
from httpx import AsyncClient
from netaddr import IPNetwork, AddrFormatError
from rich.console import Console
from search_engines import *

# Constants
USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 '
              'Safari/537.36')
REX_PHONE = compile(r"[+]\d+(?:[-\s]|)[\d\-\s]+")
REX_MAIL = compile(r"\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.']\w+)*")

class SpoofFinder:
    def __init__(self, target: str = None, loop=None):
        self.logger = Console(force_terminal=True, markup=True, emoji=True, log_path=False)
        self.loop = loop or new_event_loop()
        self.target = target
        self.client = AsyncClient(timeout=10, headers={"User-Agent": USER_AGENT})
        self.search_engines = (
            Google, Yahoo, Aol, Duckduckgo, Startpage, Dogpile, Ask, Mojeek, Qwant
        )

    async def fetch(self, url: str, as_json: bool = True) -> Union[Optional[Dict], Optional[str]]:
        """
        Fetches the given URL using httpx and handles exceptions.
        Args:
            url (str): The URL to fetch.
            as_json (bool, optional): Whether to parse the response as JSON. Defaults to True.
        Returns:
            Union[Optional[Dict], Optional[str]]: The parsed JSON response or the raw text if `as_json` is False.
        """
        try:
            response = await self.client.get(url)
            return response.json() if as_json else response.text
        except Exception as e:
            self.logger.log(f"[red]Error fetching {url}: {str(e)}")
            return None

    @staticmethod
    def parse_asn(target: str) -> str:
        """
        Parses an ASN from the given target string.
        If the target string starts with "AS", it removes the "AS" prefix and returns the remaining string.
        If the target string is a digit-only string, it returns the string as it is.
        Otherwise, it returns the target string as it is.
        Args:
            target (str): The target string to parse.
        Returns:
            str: The parsed ASN string.
        """
        if target.lower().startswith("as"):
            return target[2:]
        return target if target.isdigit() else target

    async def find_links(self, query: str) -> Optional[List[str]]:
        """
        Searches the given query using multiple search engines and returns a list of links.
        Args:
            query (str): The query to search.
        Returns:
            Optional[List[str]]: A list of links found by the search engines, or None if no links are found.
        """
        for engine in self.search_engines:
            async with engine(print_func=lambda *args, **kwargs: None) as e:
                e.set_headers({'User-Agent': USER_AGENT})
                data = await e.search(query, pages=2)
                links = data.links()
                if links:
                    return links
        return None

    async def get_asn_info(self, target: str) -> Optional[Dict]:
        """
        Fetches the ASN information for the given target string.
        Args:
            target (str): The target string to fetch ASN information for.
        Returns:
            Optional[Dict]: The ASN information as a dictionary, or None if no ASN information is found.
        """
        return await self.fetch(f"https://ipapi.co/{target}/json/") or None

    async def find_contact(self, asn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Fetches the contact information for the given ASN.
        Args:
            asn (str): The ASN to fetch contact information for.
        Returns: Tuple[Optional[str], Optional[str], Optional[str]]: A tuple containing the contact site, email,
        and phone number, or None if no contact information is found.
        """
        response = await self.fetch(f"https://rdap.arin.net/registry/autnum/{asn}", as_json=False)
        if not response:
            return None, None, None
        mail_match = REX_MAIL.search(response)
        phone_match = REX_PHONE.search(response)
        site = mail_match.group(0).split('@')[1] if mail_match else None
        return site, mail_match.group(0) if mail_match else None, phone_match.group(0) if phone_match else None

    async def fetch_spoof_data(self, asn: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Fetches the spoofing data for the given ASN from the CAIDA API and the ASRank API.
        Args:
            asn (str): The ASN to fetch spoofing data for.
        Returns: Tuple[Optional[Dict], Optional[Dict]]: A tuple containing two dictionaries. The first dictionary
        contains the spoofing data from the CAIDA API, or None if no data is found. The second dictionary contains
        the ASRank data, or None if no data is found.
        """
        return await gather(
            self.fetch(f"https://api.spoofer.caida.org/sessions?asn={asn}"),
            self.fetch(f"https://api.asrank.caida.org/v2/restful/asns/{asn}")
        )

    async def handle_asn(self, asn: str) -> None:
        """
        Handles the given ASN and fetches data from the CAIDA API and the ASRank API.
        Args:
            asn (str): The ASN to handle.
        Returns:
            None
        """
        self.logger.log(f"[bold cyan]🔍 Fetching data for ASN: AS{asn}...")
        spoof_data, asrank_data = await self.fetch_spoof_data(asn)
        if not spoof_data or not asrank_data or not asrank_data.get("data", {}).get("asn"):
            return self.logger.log(f"[bold red]❌ No data found for ASN: {asn}")
        spoof_data = spoof_data.get("hydra:member", spoof_data)
        if not spoof_data:
            return self.logger.log(f"[bold red]❌ No data found for ASN: {asn}")
        spoof_data = spoof_data[-1] if isinstance(spoof_data, list) else spoof_data
        as_name = asrank_data['data']['asn'].get('asnName', 'Unknown')
        try:
            last_check = datetime.strptime(spoof_data.get("timestamp", ''), '%Y-%m-%dT%H:%M:%S+00:00')
        except ValueError:
            last_check = None
        spoofable_localv4 = spoof_data.get("routedspoof", "") == "received"
        spoofable_internetv4 = spoof_data.get("privatespoof", "") == "sent"
        spoofable_localv6 = spoof_data.get("routedspoof6", "") == "received"
        spoofable_internetv6 = spoof_data.get("privatespoof6", "") == "sent"
        ipv4_client = spoof_data.get("client4", "")
        ipv6_client = spoof_data.get("client6", "")
        asn_val = spoof_data.get("asn4", asn)
        asn6 = spoof_data.get("asn6", "")
        site, mail, phone = await self.find_contact(asn)
        # Log main ASN details
        self.logger.log(f"[bold green]🌍 ASN Name: {as_name}")
        if asn6:
            self.logger.log(f"[bold blue]🔢 ASN6 Number: [cyan]AS{asn6}")
        if asn_val:
            self.logger.log(f"[bold blue]🔢 ASN Number: [cyan]AS{asn_val}")
        if site:
            self.logger.log(f"[bold yellow]🌐 Site: {site}")
        self.logger.log(f"[bold magenta]🏆 ASN Rank: [cyan]{asrank_data['data']['asn'].get('rank', 'N/A')}")
        # Log spoofability details
        if spoofable_localv4 or spoofable_internetv4:
            labels = [lbl for lbl in ['Local' if spoofable_localv4 else None, 'Internet' if spoofable_internetv4 else None] if lbl]
            self.logger.log(f"[bold yellow]🛡️ Spoofable IPv4: [cyan]{', '.join(labels) or 'No'}")
        elif spoofable_localv6 or spoofable_internetv6:
            labels = [lbl for lbl in ['Local' if spoofable_localv6 else None, 'Internet' if spoofable_internetv6 else None] if lbl]
            self.logger.log(f"[bold yellow]🛡️ Spoofable IPv6: [cyan]{', '.join(labels) or 'No'}")
        else:
            self.logger.log("[bold red]🛡️ Spoofable: [cyan]No")
        self.logger.log(f"[bold cyan]🌍 Country: [green]{spoof_data.get('country', 'N/A').upper()}")
        # Log client IPs
        if ipv4_client:
            self.logger.log(f"[bold cyan]🌐 Client IPv4: [yellow]{ipv4_client}")
        if ipv6_client:
            self.logger.log(f"[bold cyan]🌌 Client IPv6: [yellow]{ipv6_client}")
        # Log last check date
        if last_check:
            self.logger.log(f"[bold cyan]⏱️ Last Checked: [green]{last_check.strftime('%b %d %Y %I:%M %p')}")
        else:
            self.logger.log("[bold cyan]⏱️ Last Checked: [green]N/A")
        # Log contact information
        if mail:
            self.logger.log(f"[bold cyan]📧 Contact Email: [yellow]{mail}")
        if phone:
            self.logger.log(f"[bold cyan]📞 Contact Phone: [yellow]{phone}")
        # Log related links
        links = await self.find_links(as_name + " server")
        if site:
            site_links = await self.find_links(site)
            if site_links:
                links.extend(site_links)
        if links:
            self.logger.log("[bold green]🔗 Related Links:")
            for link in links:
                self.logger.log(f"[yellow]- {link}")

    async def _run(self) -> None:
        asn = self.target or (await ainput("Enter ASN, IP, CIDR: ")).strip()
        asn = self.parse_asn(asn)
        if "/" in asn or "-" in asn:
            try:
                asn = str(IPNetwork(asn)[0])
            except AddrFormatError as e:
                self.logger.log(f"[red]Invalid CIDR/Range: {str(e)}")
                return
        if not asn.isdigit():
            asn_info = await self.get_asn_info(asn)
            if not asn_info or not asn_info.get("asn"):
                self.logger.log("[red]No ASN info found.")
                return
            asn = asn_info["asn"].replace("AS", "") if asn_info.get("asn") else asn
        await self.handle_asn(asn)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.loop.close()

    def run(self) -> None:
        self.loop.run_until_complete(self._run())

    async def close(self):
        await self.client.aclose()

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Spoof Finder CLI")
    parser.add_argument('-t', '--target', help="Target ASN, IP, or CIDR", required=False)
    args = parser.parse_args()
    with SpoofFinder(args.target) as spoof_finder:
        spoof_finder.run()

if __name__ == "__main__":
    main()
