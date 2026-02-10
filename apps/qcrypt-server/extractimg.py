#! /usr/bin/env python3
import binascii
import os
import sys
import shutil
import json
import base64
import re
from traceback import print_exc

darkDefault = '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24" fill="none"><path fill="#FFF" d="M280-400q-33 0-56.5-23.5T200-480q0-33 23.5-56.5T280-560q33 0 56.5 23.5T360-480q0 33-23.5 56.5T280-400Zm0 160q-100 0-170-70T40-480q0-100 70-170t170-70q67 0 121.5 33t86.5 87h352l120 120-180 180-80-60-80 60-85-60h-47q-32 54-86.5 87T280-240Zm0-80q56 0 98.5-34t56.5-86h125l58 41 82-61 71 55 75-75-40-40H435q-14-52-56.5-86T280-640q-66 0-113 47t-47 113q0 66 47 113t113 47Z"/></svg>'
lightDefault = '<svg xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24" fill="none"><path fill="#000" d="M280-400q-33 0-56.5-23.5T200-480q0-33 23.5-56.5T280-560q33 0 56.5 23.5T360-480q0 33-23.5 56.5T280-400Zm0 160q-100 0-170-70T40-480q0-100 70-170t170-70q67 0 121.5 33t86.5 87h352l120 120-180 180-80-60-80 60-85-60h-47q-32 54-86.5 87T280-240Zm0-80q56 0 98.5-34t56.5-86h125l58 41 82-61 71 55 75-75-40-40H435q-14-52-56.5-86T280-640q-66 0-113 47t-47 113q0 66 47 113t113 47Z"/></svg>'
darkDefaultB64 = base64.standard_b64encode(darkDefault.encode())
lightDefaultB64 = base64.standard_b64encode(lightDefault.encode())

inputFile = 'assets/combined_aaguid.json'
pathBase = 'assets/aaguid/'
pathImg = pathBase + 'img/'
shutil.rmtree(pathImg)
os.makedirs(os.path.dirname(pathImg), exist_ok=True)

with open(inputFile, 'r') as fin:
    data = json.load(fin)
    newData = {}
    for key, value in data.items():
        if not re.match(r'^[a-zA-Z0-9_-]+$', key):
            raise ValueError(f'Invalid key format: {key}')

        if 'icon_dark' in value and value['icon_dark']:
            (darkType, darkB64) = value['icon_dark'].split(',')
            darkTypeSvg = darkType.lower().find('image/svg+xml') > 0
            darkFile = pathImg + key + '_dark.' + ('svg' if darkTypeSvg else 'png')
        else:
            darkTypeSvg = True
            darkB64 = darkDefaultB64
            darkFile = pathImg + 'default_dark.svg'

        if 'icon_light' in value and value['icon_light']:
            (lightType, lightB64) = value['icon_light'].split(',')
            lightTypeSvg = lightType.lower().find('image/svg+xml') > 0
            lightFile = pathImg + key + '_light.' + ('svg' if lightTypeSvg else 'png')
        else:
            lightTypeSvg = True
            lightB64 = lightDefaultB64
            lightFile = pathImg + 'default_light.svg'

#        print(f'{darkType}, {darkTypeSvg}, {darkFile}')
#        print(f'{lightType}, {lightTypeSvg}, {lightFile}')

        newData[key] = {
            'name': value['name'],
            'dark_file': darkFile,
            'light_file': lightFile
        }

        # ignoring the dafaults may be written multiple times
        try:
            darkData = []
            if darkTypeSvg:
                try:
                    darkData = base64.standard_b64decode(darkB64).decode()
                except binascii.Error:
                    darkData = base64.standard_b64decode(darkB64 + '==').decode()
                with open(darkFile, 'w') as fdark:
                    fdark.write(darkData)
            else:
                try:
                    darkData = base64.standard_b64decode(darkB64)
                except binascii.Error:
                    # try with extra padding (sometimes missing)
                    darkData = base64.standard_b64decode(darkB64 + '==')

                with open(darkFile, 'wb') as fdark:
                    fdark.write(darkData)
        except Exception as err:
            print(f'{darkType}, {darkTypeSvg}, {darkB64}')
            print_exc()
            sys.exit(1)

        try:
            lightData = []
            if lightTypeSvg:
                try:
                    lightData = base64.standard_b64decode(lightB64).decode()
                except binascii.Error:
                    lightData = base64.standard_b64decode(lightB64 + '==').decode()
                with open(lightFile, 'w') as flight:
                    flight.write(lightData)
            else:
                try:
                    lightData = base64.standard_b64decode(lightB64)
                except binascii.Error:
                    lightData = base64.standard_b64decode(lightB64 + '==')
                with open(lightFile, 'wb') as flight:
                    flight.write(lightData)
        except Exception as err:
            print(f'{lightType}, {lightTypeSvg}, {lightB64}')
            print_exc()
            sys.exit(1)

    with open(pathBase + 'combined.json', 'w') as fout:
        json.dump(newData, fout)
