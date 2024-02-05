from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from colorama import Fore, init
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


init(autoreset=True)

sql_str_true = '\' or 1=1 and 1=1;#'
sql_str_false = '\' or 1=1 and 1=2;#'

class sqli_scanner:
    def __init__(self, session):
        self.session = session
        self.count_sqli = 0

    def extract_forms(self, url):
        try:
            response = self.session.get(url)
            response.raise_for_status()  # Raise an exception for bad responses (4xx, 5xx)
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f'[***] Error while extracting forms: {e}')
            return []

        parsed_html = BeautifulSoup(response.content, 'html.parser')
        return parsed_html.findAll("form")

    def submit_form(self, post_url, method, post_data):
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[500, 502, 503],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session = requests.Session()
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        try:
            if method == 'post':
                return session.post(post_url, data=post_data, timeout=2)  # Set timeout as needed
            else:
                return session.get(post_url, params=post_data, timeout=2)  # Set timeout as needed
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f'[***] Error while submitting form: {e}')
            return None

    def is_resp_equal(self, resp1, resp2):
        if resp1 is None or resp2 is None:
            return False
        if resp1.status_code != resp2.status_code:
            return False
        if str(resp1.content) != str(resp2.content):
            return False
        return True

    def run_sqli_test(self, link):
        print("\n[+] Testing forms in " + link + " for SQLI\n")
        forms = self.extract_forms(link)
        count = 0
        form_count = 0

        for form in forms:
            iteration = 1
            action = form.get("action")
            post_url = urljoin(link, action)  # Ensure the import statement is present for urljoin
            method = form.get("method")
            post_data_true = {}
            post_data_false = {}
            resp_true = None
            resp_false = None

            while iteration <= 2:
                if iteration == 1:
                    curr_form = form
                elif form_count < len(self.extract_forms(link)):
                    curr_form = self.extract_forms(link)[form_count]
                else:
                    break  # Exit the loop if form_count exceeds the length of the list

                inputs_list = curr_form.findAll('input')
                for inputs in inputs_list:
                    name = inputs.get('name')
                    value = inputs.get('value')
                    input_type = inputs.get('type')
                    if input_type == 'text':
                        post_data_true[name] = sql_str_true
                        post_data_false[name] = sql_str_false
                    else:
                        post_data_true[name] = value
                        post_data_false[name] = value

                resp_true = self.submit_form(post_url, method, post_data_true)
                resp_false = self.submit_form(post_url, method, post_data_false)

                iteration += 1

            if not self.is_resp_equal(resp_true, resp_false):
                count += 1
                print(Fore.RED + '\n[***] The following form in the link ' + link + ' is vulnerable to SQL Injection.'
                                ' Security Risk: Severe.\n')
                print(form)
            form_count += 1

        if count == 0:
            print('\n[+] The link is not vulnerable to SQL Injection.\n')
            return 0
        else:
            self.count_sqli += count
            return count

