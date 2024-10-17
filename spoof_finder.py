from asyncio import new_event_loop, gather
from datetime import datetime
from re import compile, Pattern
from typing import Optional, List, Tuple, Dict, Union, Iterable

from aioconsole import ainput
from httpx import AsyncClient, Response
from netaddr import IPNetwork, AddrFormatError
from rich.console import Console
from search_engines import *  # Assuming this is a valid import

# Compiled regex for phone and email patterns
REX_PHONE: Pattern = compile(r"[+]\d+(?:[-\s]|)[\d\-\s]+")
REX_MAIL: Pattern = compile(r"\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.']\w+)*")

# User-agent for HTTP requests
USER_AGENT: str = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                   'Chrome/96.0.4664.110 Safari/537.36')


class MultipleSearchEngines(Iterable):
    def __iter__(self):
        self._current_index = 0  # Reset index for each iteration
        return self

    def __init__(self, *search_engines: object):
        self._search_engines = search_engines
        self._current_index: int = 0

    def __len__(self):
        return len(self._search_engines)

    def __next__(self) -> object:
        """Returns the next search engine."""
        if self._current_index >= len(self._search_engines):
            raise StopIteration

        search_engine = self._search_engines[self._current_index]
        self._current_index += 1
        return search_engine(print_func=lambda *args, **kwargs: None)


class SpoofFinder:
    def __init__(self, target: str, loop=None):
        self._logger: Console = Console(
            force_terminal=True,
            markup=True,
            emoji=True,
            log_path=False
        )
        self._loop = loop or new_event_loop()
        self._asn: Optional[str] = target or None
        self._client: AsyncClient = AsyncClient(timeout=10, headers={"User-Agent": USER_AGENT})
        self._search_engines: MultipleSearchEngines = MultipleSearchEngines(
            Google,
            Yahoo,
            Aol,
            Duckduckgo,
            Startpage,
            Dogpile,
            Ask,
            Mojeek,
            Qwant,
        )

    async def fetch(self, url: str, as_json: bool = True) -> Union[Optional[Dict], Optional[str]]:
        """Fetch data from a URL using async HTTP request."""
        try:
            response: Response = await self._client.get(url)
            if as_json:
                return response.json()
            return response.text
        except Exception as e:
            self._logger.log(f"[red]Error fetching {url}: {str(e)}")
            return None

    @staticmethod
    def parse_asn(target: str) -> str:
        """Determine if input is an ASN and return a cleaned version."""
        if target.lower().startswith("as") or target.isdigit():
            return target[2:] if target.lower().startswith("as") else target
        return target

    async def find_links(self, query: str) -> Optional[List[str]]:
        """
        Searches for related links based on the given query using multiple search engines.

        :param query: str The search query
        :return: List[str] A list of related links if found, otherwise None
        """
        links: List[str] = []

        search_tasks = [
            self.search_engine_task(engine, query) for engine in self._search_engines
        ]

        results = await gather(*search_tasks)

        for items in results:
            if items:
                links.extend(items)
                break  # Return first found links

        return links if links else None

    @staticmethod
    async def search_engine_task(engine, query: str) -> List[str]:
        """
        This is a helper method to create a task for searching a search engine.

        :param engine: A search engine object
        :param query: The search query
        :return: A list of URLs from the search results if found, otherwise an empty list
        """
        try:
            async with engine as e:
                data = await e.search(query, pages=2)
                return data.links() if data else []
        except:
            return []

    async def get_asn_info(self, target: str) -> Optional[Dict]:
        """
        Retrieves information about an ASN from ipapi.co.

        :param target: The ASN to look up
        :return: A dictionary containing the ASN information if found, otherwise None
        """
        response: Optional[Dict] = await self.fetch(f"https://ipapi.co/{target}/json/")
        return response if response else None

    async def find_contact(self, asn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Finds contact information for a given ASN from ARIN's RDAP service.

        :param asn: The ASN to look up
        :return: A tuple containing the domain name, email, and phone number of the contact
        """
        response: Optional[str] = await self.fetch(f"https://rdap.arin.net/registry/autnum/{asn}", as_json=False)
        if not response:
            return None, None, None

        mail = REX_MAIL.search(response)
        phone = REX_PHONE.search(response)

        site: Optional[str] = mail.group(0).split('@')[1] if mail else None
        return site, mail.group(0) if mail else None, phone.group(0) if phone else None

    async def fetch_spoof_data(self, asn: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Retrieves data from CAIDA's Spoofer API and AS Rank API.

        :param asn: The ASN to query
        :return: A tuple containing the Spoofer API response and the AS Rank API response
        """
        spoof_data, asrank_data = await gather(
            self.fetch(f"https://api.spoofer.caida.org/sessions?asn={asn}"),
            self.fetch(f"https://api.asrank.caida.org/v2/restful/asns/{asn}")
        )
        return spoof_data, asrank_data

    async def handle_asn(self, asn: str) -> None:
        """
        Handles the logic for retrieving and printing information about a given ASN.

        :param asn: The ASN to query
        :return: None
        """
        self._logger.log(f"[cyan]Getting information for ASN: {asn}...")

        spoof_data, asrank_data = await self.fetch_spoof_data(asn)

        if not spoof_data or not asrank_data or asrank_data["data"]["asn"] is None:
            self._logger.log(f"[red]No data found for ASN: {asn}")
            return

        as_name: str = asrank_data['data']['asn']['asnName']
        last_check: datetime = datetime.strptime(spoof_data["hydra:member"][-1]["timestamp"], '%Y-%m-%dT%H:%M:%S+00:00')
        spoofable: bool = spoof_data["hydra:member"][-1]["routedspoof"] == "received"

        site, mail, phone = await self.find_contact(asn)
        links: Optional[List[str]] = await self.find_links(as_name + " server")
        if site:
            site_links = await self.find_links(site)
            if site_links:
                links.extend(site_links)

        self._logger.log(f"[green]ASN Name: {as_name}")
        self._logger.log(f"[green]Spoofable: {'Yes' if spoofable else 'No'}")
        self._logger.log(f"[green]Last Checked: {last_check.strftime('%b %d %Y %I:%M %p')}")
        if mail:
            self._logger.log(f"[blue]Contact Email: {mail}")
        if phone:
            self._logger.log(f"[blue]Contact Phone: {phone}")
        if links:
            self._logger.log(f"[green]Related Links:")
            for link in links:
                self._logger.log(f"[yellow]- {link}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._loop.run_until_complete(self.close())

    async def _run(self) -> None:
        """Main logic for handling user input and making requests."""
        asn: str = self._asn or (await ainput("Enter ASN, IP, CIDR: ")).strip()
        asn = self.parse_asn(asn)

        if "/" in asn or "-" in asn:
            try:
                asn = str(IPNetwork(asn)[0])
            except AddrFormatError as e:
                self._logger.log(f"[red]Invalid CIDR/Range: {str(e)}")
                return

        if not asn.isdigit():
            asn_info: Optional[Dict] = await self.get_asn_info(asn)

            if asn_info is None or not asn_info.get("asn"):
                self._logger.log("[red]No ASN info found.")
                return
            asn = asn_info["asn"]

        await self.handle_asn(asn)

    def run(self) -> None:
        """Run the spoof finder."""
        self._loop.run_until_complete(self._run())

    async def close(self):
        await self._client.aclose()


def main() -> None:
    """Main entry point with CLI support."""
    import argparse

    parser = argparse.ArgumentParser(description="Spoof Finder CLI")
    parser.add_argument('-t', '--target', help="Target ASN, IP, or CIDR", required=False)
    args: argparse.Namespace = parser.parse_args()

    with SpoofFinder(args.target) as spoof_finder:
        spoof_finder.run()


if __name__ == "__main__":
    main()
