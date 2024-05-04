from setuptools import setup

setup(
    name="aslrCTF",
    author="mosafaf15",
    author_email="mosafaf84@gmail.com",
    version='1.0.0',
    packages=[
        'aslrCTF',
    ],
    install_requires=[
        'pwn',
        'pwntools',
        'ropper',
        'colorama',
        'tabulate',
        'string',
        'platform',
        # 'inspect',
        # 'time',
        'python-time'
    ]
)