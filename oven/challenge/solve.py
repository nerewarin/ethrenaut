from Crypto.Util.number import getPrime, long_to_bytes

from ctf.oven.challenge.challenge import BITS, custom_hash

# 128 bytes
t = 43089091414446054240959175400654083336154991142155926085081901080892722017399380772590355143553573334061801127794753834232511949628624425179677845387174341510618390242691867846237376486424343821151368372726224359929374984499566375876339016845830978699723094909949945499933430888099386656799988990410952699574
# 128 bytes
r = 110315970370538055532728885780646047314570040750872520881417441545315291810901726396885673266257831987014868911267616237858284155893979316336926543046495969361743807157755890429744665806335019611950658974762481444363866267036260132670050177842295713793582234414888086195737741771882580819376984288941138422289

# 128 bytes
p = 110315970370538055532728885780646047314570040750872520881417441545317897655328635420053674396871009325890131166259211982873660781296580758384147447120050687997879253731192754436042705553721819789696050668407378214329987996967760316257274895322472239111059799775584044735132818211767130626098458112276619454729
# 1 byte
g = 2
# 128 bytes
y = 34646046006435504334385139010919556171932398511489003712232167314388890330275826237254127947988763179354147733133961408802543407541480791657678966800185164375262507534613607708985211488881700757522822774574450628034979743376976872056599228741441197967359658553348244818229847628428910437413404580479586276937

#
# for i in range(10):
#     print(getPrime(BITS))


def _nullify_endian_bytes(orig, n):
    res = orig[:n]
    for i in range(len(orig) - n):
        res += b"\x00"
    return res


def orig():
    # 1 byte
    lg = long_to_bytes(g)
    # 128 bytes
    ly = long_to_bytes(y)
    # 128 bytes
    lt = long_to_bytes(t)
    # 257 bytes
    l = lg + ly + lt
    # but custom_hash uses only 32 biggest bytes
    # 96 bytes
    return custom_hash(l)


def simplified():
    lg = long_to_bytes(g)
    ly = _nullify_endian_bytes(long_to_bytes(y), 15 + 16)
    lt = b"\x00" * 128
    l = lg + ly + lt

    return custom_hash(l)


if __name__ == '__main__':
    o = orig()
    s = simplified()
    assert o == s, "We use only 31 biggest bytes of Y and do not use T in custom_hash hash function at all!"