from utils.config import Config
from utils.util import random_choices, exec_system, load_file
import os


class MassDNS:
    def __init__(self, domains=None, massdns_bin=None, dns_server=None, tmp_dir=None):
        self.domains = domains
        self.tmp_dir = tmp_dir
        self.dns_server = dns_server
        self.domaingen_output_path = os.path.join(tmp_dir,
                                                "domaingen_{}".format(random_choices()))
        self.massdns_output_path = os.path.join(tmp_dir,
                                               "massdns_{}".format(random_choices()))
        self.massdns_bin = massdns_bin

    def domaingen(self):
        with open(self.domaingen_output_path, "w") as f:
            for domain in self.domains:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

    def massdns(self):
        command = [self.massdns_bin, "-q",
                   "-r {}".format(self.dns_server),
                   "-o S",
                   "-w {}".format(self.massdns_output_path),
                   "-s {}".format(Config.DOMAIN_BRUTE_CONCURRENT),
                   self.domaingen_output_path,
                   "--root"
                   ]

        exec_system(command)

    def parse_massdns_output(self):
        output = []
        lines = load_file(self.massdns_output_path)
        for line in lines:
            data = line.split(" ")
            if len(data) != 3:
                continue
            domain, _type, record = data
            item = {
                'domain': domain.strip('.'),
                'type': _type,
                'record': record.strip().strip('.')
            }
            output.append(item)

        self._delete_file()
        return output

    def _delete_file(self):
        try:
            os.unlink(self.domaingen_output_path)
            os.unlink(self.massdns_output_path)
        except Exception as e:
            pass

    def run(self):
        self.domaingen()
        self.massdns()
        output = self.parse_massdns_output()
        return output


def mass_dns(base_domain, words):
    domains = []
    for word in words:
        word = word.strip()
        if word:
            domains.append("{}.{}".format(word, base_domain))
    domains.append(base_domain)
    mass = MassDNS(domains, massdns_bin=Config.MASSDNS_BIN,
                   dns_server=Config.DNS_SERVER, tmp_dir=Config.TMP_PATH)
    return mass.run()
