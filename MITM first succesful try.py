from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
block_size = 32
text_no_bytes = input()
text = bytes(text_no_bytes, encoding = 'utf-8')
aes_key_1 = b'ebjdefg2jjkl1nsp'
aes_key_2 = b'atcdgfg5jjjlhnpo'
crypto_thing_1 = AES.new(aes_key_1, AES.MODE_ECB)
crypto_thing_2 = AES.new(aes_key_2, AES.MODE_ECB)

cipher_text_1 = crypto_thing_1.encrypt(pad(text, block_size))
cipher_text_f = crypto_thing_2.encrypt(pad(cipher_text_1, block_size))
print(f'\nВот шифрованный текст: {cipher_text_f.hex()}')

decipher_text_1 = unpad(crypto_thing_2.decrypt(cipher_text_f), block_size)
decipher_text_2 = crypto_thing_1.decrypt(decipher_text_1)
decipher_text_2 = unpad(crypto_thing_1.decrypt(decipher_text_1), block_size)

print(f'\nВот расшифрованный текст: {decipher_text_2.decode('utf-8')}')

"""MITM BEGIN UNDER"""
may_key_massive = [b'usdijwek19aj8rgn',b'wuiqoe3h4j5kshgb',b'k13kh2jsyqowi4jf',b'atcdgfg5jjjlhnpo',b'h12j3kgfiejrthyn',b'ebjdefg2jjkl1nsp']
m1_table = bytearray()
stealed_piece_of_text = bytes(text_no_bytes, encoding = 'utf-8')
for k1 in may_key_massive:
    decrypt_thing_for_MITM = AES.new(k1, AES.MODE_ECB)
    decrypted_2nd = decrypt_thing_for_MITM.decrypt(cipher_text_f)
#Использовал этот вывод для отладки, больше он не нужен     print(f'\nРасшифрованная штука в таблицу m1:{decrypted_2nd}')
    m1_table += decrypted_2nd
k_candidat_1 = bytes
for k2 in may_key_massive:
    crypto_thing_for_MITM = AES.new(k2, AES.MODE_ECB)
    crypto_mitm_m2_value = crypto_thing_for_MITM.encrypt(pad(stealed_piece_of_text, block_size))
#Использовал этот вывод для отладки, больше он не нужен     print(f'\nРасшифрованная штука в таблицу m2(в нашем коде её нет, т.к. данные сравниваются во время каждого прохождения цикла, а не из двух готовых таблиц, но вообще решение MITM в общем случае предполагает её): {crypto_mitm_m2_value}')
    if crypto_mitm_m2_value in m1_table:
        k_candidat_1 = k2
#Почему то находит только 1(подразумевается и "один" и "первый") ключ, пока что предполагаю что проблема в ососбенности работы массивов байтов
#Я понял свою глупость, мы же буквально "встречаемся посередине", преодолев второй слой защиты перебором, значит он и должен выдавать мне один ключ, нужный для первой расшифровки и всё, по идее так, значит второй ключ мы ищем уже после того как нашли первый
crypto_things_for_MITM_key2 = AES.new(k_candidat_1, AES.MODE_ECB)
crypto_text_ciphered_1 = crypto_things_for_MITM_key2.encrypt(pad(stealed_piece_of_text, block_size))
k_candidat_2 = bytes
for k3 in may_key_massive:
    ctfMk2 = AES.new(k3, AES.MODE_ECB)
    ctc2 = ctfMk2.encrypt(crypto_text_ciphered_1)
    if ctc2 in cipher_text_f:
        k_candidat_2 = k3
print(f'\nВот такие кандидаты в ключи получились:{k_candidat_1} и {k_candidat_2}')
#decrypted_stealed_text = crypto_things_for_MITM_key2.decrypt()
decrypted_stealed_thing = AES.new(k_candidat_2, AES.MODE_ECB)
decrypted_stealed_text_layer_2 = decrypted_stealed_thing.decrypt(cipher_text_f)
decrypted_stealed_text_layer_1 = crypto_things_for_MITM_key2.decrypt(unpad(decrypted_stealed_text_layer_2,block_size))
print(f'\n Перехваченное и расшифрованное сообщение:{decrypted_stealed_text_layer_1.decode()}')
