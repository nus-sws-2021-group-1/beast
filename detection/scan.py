#!/usr/bin/python3

from sslyze import *
import sys

# Usage: python scan.py [host] [port]

location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(sys.argv[1], sys.argv[2])
try:
    server_info = ServerConnectivityTester().perform(location)
except ConnectionToServerFailed as e:
    pass

scanner = Scanner()

scan_request = ServerScanRequest(
    server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.TLS_1_0_CIPHER_SUITES}
)
scan_result = scanner.start_scans([ scan_request ])

for server_scan_result in scanner.get_results():
    try:
        tls1_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_0_CIPHER_SUITES]
        print('Cipher suites:')
        for suite in tls1_result.accepted_cipher_suites:
            suite_name = suite.cipher_suite.name
            print(f"{suite_name}", end='')
            if 'CBC' in suite_name:
                print(' <- VULNERABLE TO BEAST')
            else:
                print('')
    except KeyError:
        pass

    try:
        certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
        print('\nCertificate info:')
        for deployment in certinfo_result.certificate_deployments:
            print(deployment.received_certificate_chain_as_pem[0])
    except KeyError:
        pass
