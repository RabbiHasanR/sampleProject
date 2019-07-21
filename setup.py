import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
   name='test',
   version='1.0',
   description='A useful module',
   author='Rabbi',
   author_email='jasrabbi50@gmail.com',
   packages=['example_pkg'],  #same as name
   install_requires=['nmap'], #external packages as dependencies
)