import logging

from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv11ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv13ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv30ScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.server_connectivity_tester import ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.synchronous_scanner import SynchronousScanner

# In the case of AWS Lambda, the root logger is used BEFORE our Lambda handler
# runs, and this creates a default handler that goes to the console.  Once
# logging has been configured, calling logging.basicConfig() has no effect.  We
# can get around this by removing any root handlers (if present) before calling
# logging.basicConfig().  This unconfigures logging and allows --debug to
# affect the logging level that appears in the CloudWatch logs.
#
# See
# https://stackoverflow.com/questions/1943747/python-logging-before-you-run-logging-basicconfig
# and
# https://stackoverflow.com/questions/37703609/using-python-logging-with-aws-lambda
# for more details.
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

        # Set up logging
        log_level = logging.DEBUG
        logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s',
                            level=log_level)

# The default ports to check when scanning for SMTP servers
DEFAULT_SMTP_PORTS = {25, 465, 587}

# The default scan types to run
DEFAULT_SCAN_TYPES = {
    'mx': True,
    'starttls': True,
    'spf': True,
    'dmarc': True
}


def handler(event, context):
    """Handler for all Lambda events

    The event parameter is a dictionary containing the following keys
    and value types:
    * hostname - A string containing the hostname to be scanned.  For
      example, "dhs.gov".
    * port - An integer specifying the port to be scanned.  If omitted
      then the default value of 443 is used.
    * timeout - An integer denoting the number of seconds to wait when
      creating a connection.  If omitted then the default value of 5
      is used.
    * starttls_smtp - A boolean value denoting whether to try to use
      STARTTLS after connecting to an SMTP server.  This option should
      be True is connecting to an SMTP host and otherwise False.  If
      omitted then the default value of False is used.
    * scan_tlsv10 - A boolean value denoting whether to scan for TLS
      version 1.0 ciphers. If omitted then the default value of False
      is used.
    * scan_tlsv11 - A boolean value denoting whether to scan for TLS
      version 1.1 ciphers. If omitted then the default value of False
      is used.
    * scan_tlsv12 - A boolean value denoting whether to scan for TLS
      version 1.2 ciphers. If omitted then the default value of False
      is used.
    * scan_tlsv13 - A boolean value denoting whether to scan for TLS
      version 1.3 ciphers. If omitted then the default value of False
      is used.
    * scan_sslv20 - A boolean value denoting whether to scan for SSL
      version 2.0 ciphers. If omitted then the default value of False
      is used.
    * scan_sslv30 - A boolean value denoting whether to scan for SSL
      version 3.0 ciphers. If omitted then the default value of False
      is used.
    * scan_cert_info - A boolean value denoting whether to return
      certificate information. If omitted then the default value of
      False is used.

    Parameters
    ----------
    event : dict
        A dictionary containing the scan parameters, as described
        above.

    context : LambdaContext
        The context for the Lambda function.  See the corresponding
        AWS documentation for more details:
        https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html

    Returns
    -------
    OrderedDict
        An OrderedDict specifying the fields of the
        trustymail.domain.Domain object resulting from the scan
        activity.
    """
    logging.info('AWS Event was: {}'.format(event))

    # Extract some variables from the event dictionary
    hostname = event['hostname']
    port = event.get('port', 443)
    timeout = event.get('timeout', 5)
    starttls_smtp = event.get('starttls_smtp', False)
    scan_tlsv10 = event.get('scan_tlsv10', False)
    scan_tlsv11 = event.get('scan_tlsv11', False)
    scan_tlsv12 = event.get('scan_tlsv12', False)
    scan_tlsv13 = event.get('scan_tlsv13', False)
    scan_sslv20 = event.get('scan_sslv20', False)
    scan_sslv30 = event.get('scan_sslv30', False)
    scan_cert_info = event.get('scan_cert_info', False)

    # Initialize sslyze
    protocol = TlsWrappedProtocolEnum.PLAIN_TLS
    if starttls_smtp:
        protocol = TlsWrappedProtocolEnum.STARTTLS_SMTP

    try:
        server_tester = ServerConnectivityTester(hostname=hostname,
                                                 port=port,
                                                 tls_wrapped_protocol=protocol)
        server_info = server_tester.perform(network_timeout=timeout)
    except ServerConnectivityError:
        logging.error('Unable to connect to {}:{}'.format(hostname, port),
                      exc_info=True, stack_info=True)
        return None
    except Exception:
        logging.error('Unable to connect to {}:{}'.format(hostname, port),
                      exc_info=True, stack_info=True)
        return None

    scanner = SynchronousScanner(network_timeout=timeout)

    # Perform the scans
    if scan_tlsv10:
        logging.debug('Performing TLSv1.0 scan')
        tlsv10 = scanner.run_scan_command(server_info, Tlsv10ScanCommand())
        logging.debug('tlsv10 = {}'.format(tlsv10))
    if scan_tlsv11:
        logging.debug('Performing TLSv1.1 scan')
        tlsv11 = scanner.run_scan_command(server_info, Tlsv11ScanCommand())
        logging.debug('tlsv11 = {}'.format(tlsv11))
    if scan_tlsv12:
        logging.debug('Performing TLSv1.2 scan')
        tlsv12 = scanner.run_scan_command(server_info, Tlsv12ScanCommand())
        logging.debug('tlsv12 = {}'.format(tlsv12))
    if scan_tlsv13:
        logging.debug('Performing TLSv1.3 scan')
        tlsv13 = scanner.run_scan_command(server_info, Tlsv13ScanCommand())
        logging.debug('tlsv13 = {}'.format(tlsv13))
    if scan_sslv20:
        logging.debug('Performing SSLv2 scan')
        sslv20 = scanner.run_scan_command(server_info, Sslv20ScanCommand())
        logging.debug('sslv20 = {}'.format(sslv20))
    if scan_sslv30:
        logging.debug('Performing SSLv3 scan')
        sslv30 = scanner.run_scan_command(server_info, Sslv30ScanCommand())
        logging.debug('sslv30 = {}'.format(sslv30))
    if scan_cert_info:
        logging.debug('Performing certificate scan')
        cert_info = scanner.run_scan_command(server_info,
                                             CertificateInfoScanCommand())
        logging.debug('cert_info = {}'.format(cert_info))

    return None
