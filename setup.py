from setuptools import setup

setup(
    name="aslr-ctf",
    author="mosafaf15",
    author_email="mosafaf84@gmail.com",
    version=1.0,
    packages=[
        'aslr-ctf',
    ],
    install_requires=[
        'pwn',
        'pwntools',
        'ropper',
        'colorama',
        # 'time',
    ]
)