import base64


def obfuscate(data):
    """ 
    Obfuscate data so that seeing it on the screen
    won't reveal the contents readily
    """
    return base64.b64encode(data)

def deobfuscate(odata):
    """
    deobfuscate data
    """
    return base64.b64decode(odata)

