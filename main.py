#!/usr/bin/env python3

import argparse
import oci
import requests


# Busca os IPs do site da CloudFlare
def fetch_ips(url):
    try:
        response = requests.get(url)

        if response.status_code == 201:
            raise ValueError(f"Error: Received status code {response.status_code} from {url}")

        # Cada IP está em uma linha
        ip_list = response.text.splitlines()
        return ip_list

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return []


# Configurando o cliente do OCI
def create_network_client():
    # ~/.oci/config
    config = oci.config.from_file()

    return oci.core.VirtualNetworkClient(config)


# Lista as security rules do NSG, filtrando pela descrição
def list_ingress_security_rules(network_client, nsg_id, description):
    try:
        response = network_client.list_network_security_group_security_rules(nsg_id, direction="INGRESS")

        if not response.data:
            return {}

        current_ips = {}
        for rule in response.data:
            if rule.description == description:
                current_ips[rule.source] = rule.id

        return current_ips

    except oci.exceptions.ServiceError as e:
        print(f"Error fetching security rules: {e}")
        return {}


# Adiciona um conjunto de IPS ao NSG
def add_ips_to_nsg(network_client, nsg_id, description, ips):
    # @TODO: só permite até 25 IPs por vez, mas atualmente temos 22 na CloudFlare (15 ipv4 + 7 ipv6)

    rules = []
    for ip in ips:
        # Montar a lista de IPs a serem adicionados
        # @link https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.AddSecurityRuleDetails.html#oci.core.models.AddSecurityRuleDetails.protocol
        ingress_security_rule = oci.core.models.AddSecurityRuleDetails(
            direction="INGRESS",
            protocol="6",  # 6 = TCP
            source=ip,
            source_type="CIDR_BLOCK",
            description=description,
            tcp_options=oci.core.models.TcpOptions(source_port_range=443, destination_port_range=443)
        )
        rules.append(ingress_security_rule)

    details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
        security_rules=rules
    )

    return network_client.add_network_security_group_security_rules(
        nsg_id,
        details
    )


def remove_security_rule_ids(network_client, nsg_id, rule_ids):
    details = oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
        security_rule_ids=list(rule_ids.values())
    )

    return network_client.remove_network_security_group_security_rules(
        nsg_id,
        details
    )


def main(nsg_id, description):
    # Busca as regras do NSG
    network_client = create_network_client()
    current_ips = list_ingress_security_rules(network_client, nsg_id, description)

    # Busca os IPs da CloudFlare
    new_ipv4_ips = fetch_ips("https://www.cloudflare.com/ips-v4")

    # @FIXME: minha conta está retornando um "is not applicable for IPv6 security rule", acho que não habilitei IPV6
    # new_ipv6_ips = fetch_ips("https://www.cloudflare.com/ips-v6")
    new_ipv6_ips = []

    new_ips = new_ipv4_ips + new_ipv6_ips

    # IPs que estão na lista da CloudFlare mas não no NSG
    ips_to_be_added = []
    for ip in new_ips:
        if ip not in current_ips:
            ips_to_be_added.append(ip)

    # IPs que estão no NSG mas não na lista da CloudFlare
    rule_ids_to_be_removed = {}
    for ip in current_ips.keys():
        if ip not in new_ips:
            rule_ids_to_be_removed[ip] = current_ips[ip]

    if len(ips_to_be_added):
        print("Adicionando IPs:")
        print(ips_to_be_added)
        add_ips_to_nsg(network_client, nsg_id, description, ips_to_be_added)

    if len(rule_ids_to_be_removed):
        print("Removendo IPs:")
        print(rule_ids_to_be_removed)
        remove_security_rule_ids(network_client, nsg_id, rule_ids_to_be_removed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("CloudFlare <-> OCI integration")
    parser.add_argument(
        "nsg_id",
        help="ID do Network Security Group",
        type=str
    )
    parser.add_argument(
        "--description",
        help="Descrição das regras a serem adicionadas (padrão: CloudFlare)",
        default="CloudFlare",
        required=False,
        type=str
    )
    args = parser.parse_args()
    main(args.nsg_id, args.description)
