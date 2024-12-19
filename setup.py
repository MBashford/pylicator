from setuptools import setup

VERSION = "0.1.0"
DESCRIPTION = "A SNMP trap exploder/forwarder implemented in python"
LONG_DESCRIPTION = """
A SNMP trap exploder/forwarder implemented in python. Enables logging received 
traps using python-asn1 to perform a naive decode of the SNMP PUD
"""

setup(
    name="pylicator",
    version=VERSION,
    author="Milo Bashford",
    author_email="milobashford@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    packages=["pylicator"],
    install_requires=["asn1"]
)