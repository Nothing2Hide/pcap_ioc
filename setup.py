from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pcap_ioc',
    version='0.1.2',
    description='Python library extracting potential IOCs from a pcap file',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Nothing2Hide/pcapanalysis',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='threat-intel',
    install_requires=[
        'pyshark==0.4.2.2',
        'IPy==0.83',
        'pymisp==2.4.101'
    ],
    license='MIT',
    packages=['pcap_ioc'],
    entry_points= {
        'console_scripts': [ 'pcap_ioc=pcap_ioc.cli:main' ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
