from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pcapanalysis',
    version='0.1',
    description='Python library extracting potential IOCs from a pcap file',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/pcapanalysis',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='osint',
    install_requires=[
        'pyshark==0.4.2.2'
    ],
    license='MIT',
    packages=['pcapanalysis'],
    entry_points= {
        'console_scripts': [ 'pcap=pcapanalysis.cli:main' ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
