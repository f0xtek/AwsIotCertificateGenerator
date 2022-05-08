"""
Create & download a certificate bundle for a new AWS IoT Thing.
"""

import logging
import random
import os
import time

import boto3
import requests


def request_keys_and_certificate(
    client: boto3.client, retries: int = 5, backoff_in_seconds: int = 1
) -> dict:
    """
    Create the certificate & keys using the AWS SDK.

    :param client: a boto3 iot client
    :param retries: number of retries for throttled requests
    :param backoff_in_seconds: number of seconds between retries
    :return: certificate bundle
    """
    request_tries = 0
    while True:
        try:
            return client.create_keys_and_certificate(setAsActive=True)
        except (
            client.exceptions.ThrottlingException,
            client.exceptions.ServiceUnavailableException,
        ):
            # if being throttled, retry with exponential backoff
            if isinstance(client.exceptions.ThrottlingException):
                logging.warning("Request is being throttled!")
                if request_tries == retries - 1:
                    raise
                sleep = backoff_in_seconds * 2**request_tries + random.uniform(
                    0, 1
                )
                logging.info("Retrying in %d seconds...", sleep)
                time.sleep(sleep)
                request_tries += 1
            else:
                logging.fatal("IoT Service unavailable!")
                raise
        except client.exceptions.UnauthorizedException as err:
            msg = f"Unauthorized: {str(err)}"
            logging.fatal(msg)
            print(msg)
            raise


def get_certificate(bundle: dict) -> str:
    """
    Get the certificate PEM from the certificate bundle

    :param bundle: a certificate bundle
    :return: the PEM encoded certificate in string format
    """
    return bundle["certificatePem"]


def get_private_key(bundle: dict) -> str:
    """
    Get the private key from the certificate bundle

    :param bundle: a certificate bundle
    :return: the private key in string format
    """
    return bundle["keyPair"]["PrivateKey"]


def get_public_key(bundle: dict) -> str:
    """
    Get the public key from the certificate bundle

    :param bundle: a certificate bundle
    :return: the public key in string format
    """
    return bundle["keyPair"]["PublicKey"]


def get_root_ca(
    url: str = "https://www.amazontrust.com/repository/AmazonRootCA1.pem",
) -> bytes:
    """
    Get the Amazon Root Certificate Authority (CA) contents
    :param url: the URL of the Amazon CA file
    :return: the content of the CA file as bytes
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.content
    except requests.exceptions.HTTPError as err:
        logging.error("Error occurred requesting Root CA: %s", str(err))
        raise
    except requests.exceptions.ConnectionError as err:
        logging.error("Error downloading root CA %s", str(err))
        raise
    except requests.exceptions.Timeout:
        logging.error("Timeout downloading Root CA data.")
        raise


def download_certificate(certificate_str: str, path: str = os.curdir) -> None:
    """
    Download the certificate PEM to a local file

    :param certificate_str: the PEM encoded certificate in string format
    :param path: a path to save the certificate file
    :return: None
    """
    with open(f"{path}/cert.crt", "w", encoding="utf-8") as cert_file:
        cert_file.write(certificate_str)


def download_private_key(private_key_str: str, path: str = os.curdir) -> None:
    """
    Download the private key to a local file

    :param private_key_str: the private key data in string format
    :param path: a path to save the private key file
    :return: None
    """
    with open(f"{path}/private.key", "w", encoding="utf-8") as private_key_file:
        private_key_file.write(private_key_str)


def download_public_key(public_key_str: str, path: str = os.curdir) -> None:
    """
    Download the public key to a local file

    :param public_key_str: the public key data in string format
    :param path: a path to save the public key file
    :return: None
    """
    with open(f"{path}/public.key", "w", encoding="utf-8") as public_key_file:
        public_key_file.write(public_key_str)


def download_root_ca(root_ca_str: bytes, path: str = os.curdir) -> None:
    """
    Download the root CA PEM to a local file

    :param root_ca_str: the PEM encoded root CA in string format
    :param path: a path to save the root CA file
    :return: None
    """
    with open(f"{path}/root_ca.cer", "wb", encoding="utf-8") as root_ca_file:
        root_ca_file.write(root_ca_str)


if __name__ == "__main__":
    iot = boto3.client("iot")
    cert_bundle = request_keys_and_certificate(iot)
    download_certificate(get_certificate(cert_bundle))
    download_public_key(get_public_key(cert_bundle))
    download_private_key(get_private_key(cert_bundle))
    download_root_ca(get_root_ca())
