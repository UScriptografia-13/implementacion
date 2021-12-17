# Cryptocurrencies based on a central entity
This proyect helps to understand the cryptography bellow cryptocurrencies, specific those who are based on a central entity such as a bank.

## Installation
You can install dependencies using pip:
`$pip install -r requirements.txt`

## Elliptic curve
How to create elliptic curves:
`$python .\ellipticCurve.py` will generate a default Nist P-256 elliptic curve
You can also specify the curve wanted:
`$python .\ellipticCurve.py -t TYPE` or `$python .\ellipticCurve.py --type TYPE` with `TYPE` equals to one of the following values `P-256`, `P-384`, `P521`

How to export elliptic curves:
`$python .\ellipticCurve.py -o PATH` or `$python .\ellipticCurve.py --output PATH` will create an elliptic curve and its key will be exported to `PATH`

How to import elliptic curves:
`$python .\ellipticCurve.py -iK PATH` or `$python .\ellipticCurve.py --import_key PATH` will set the curve to the imported one.
