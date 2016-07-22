from setuptools import setup, find_packages

setup(
    name='dmarc_milter',
    packages=find_packages(exclude=('tests', )),
    install_requires=[
        'peewee',
        'pymilter',
    ],
    entry_points = {
        'console_scripts': [
          'dmarc-milter = dmarc_milter:main',
        ],
    },
)