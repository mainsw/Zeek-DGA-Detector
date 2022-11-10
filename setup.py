from setuptools import setup, find_packages

setup(
    name='zeekdga',
    version='0.0.2',
    description='DGA Domain Detector utilizing Zeek DNS logs and Deep Learning',
    author='mainsw',
    url='https://github.com/mainsw/Zeek-DGA-Detector.git',
    license='Apache-2.0',
    packages=['src'],
    install_requires=[
        'dgaintel==2.3',
        'slack-sdk==3.19.2',
        'zat==0.4.4'
    ],
    python_requires='>=3.7',
    extras_require={'es7': ['elasticsearch==7.0.0'], 'es8': ['elasticsearch==8.0.0']},
    scripts=['src/zeekdga.py']
)