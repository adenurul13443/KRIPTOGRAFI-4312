import streamlit as st
import pandas as pd

st.set_page_config(page_title="Advanced Encryption Standard (AES)", 
                   page_icon="img\img-aes-logo.png")
st.markdown("""
    <style>
        .stButton>button {
            color: cyan;
            font-weight: bold;
            background-color: black;
            border : 1px solid cyan;
        }
        .stButton>button:hover{
            color: black;
            font-weight: bold;
            background-color: #00CED1;
        }
        .stButton>button:focus{
            color: cyan;
            font-weight: bold;
            background-color: black;
            border : 1px solid cyan;
        }
        .stButton>button:focus:hover{
            color: black;
            font-weight: bold;
            background-color: #00CED1;
        }
    </style>
    """, 
    unsafe_allow_html=True,
)

def main():
    st.markdown("<h1 style='color:cyan'>Advanced Encryption Standard (AES)</span>", unsafe_allow_html=True)
    st.markdown("<h6 style='color:cyan'>This application was developed by Ari, Darren, and Arden </h6>", unsafe_allow_html=True)

    st.success("Welcome to my Application. Please input your key and plain text in sidebar.")
    
    with st.sidebar:
        st.title("Enter Your Key and Plain Text Here ")

        key = st.text_input("Enter Key (Must be 16 character(128 bits)) : ", "")
        if key:
            st.write(f"Key : {key}")

        plain_text = st.text_input("Enter Plain Text (Must be 16 character(128 bits)) : ", "")
        if plain_text:
            st.write(f"Plain Text : {plain_text}")

        plain_text_sec = st.text_input("Enter Modify Plain Text", "")
        if plain_text_sec:
            st.write(f"Modify Plain Text : {plain_text_sec}")


        encrypt_decrypt_button = st.button("Encrypt and Decrypt")
    
    if encrypt_decrypt_button:
        if not key or not plain_text or not plain_text_sec:
            st.error("Key and Plain Text can't be empty")
            return

        st.title("Your Input")

        def Text2Hex(s):
            return s.encode("utf-8").hex()
        
        key = Text2Hex(key)
        key_length = len(key) * 4

        plain_text = Text2Hex(plain_text)
        plain_text_length = len(plain_text) * 4

        plain_text_sec = Text2Hex(plain_text_sec)
        plain_text_length_sec = len(plain_text_sec) * 4

        data = {
            "Hex format": [key, plain_text, plain_text_sec],
            "Length": [f"{key_length} bits", f"{plain_text_length} bits", f"{plain_text_length_sec} bits"]
        }

        df = pd.DataFrame(data, index=['Key', 'Plain Text', 'Modify Plain Text'])

        st.table(df)

        if len(key)*4 != 128 or len(plain_text)*4 != 128 or len(plain_text_sec)*4 != 128:
            st.error("The key and both plain text length should be 128 bits.")
        else:
            w0 = key[0:8]
            w1 = key[8:16]
            w2 = key[16:24]
            w3 = key[24:32]

            Ws = [w0, w1, w2, w3]

            with st.expander("The Ws"):
                data = {f"w{i}": Ws[i] for i in range(4)}
                df = pd.DataFrame(data, index=["Value"]) 
                st.table(df)

            def LS_1_Byte(s):
                new_s = s[2:] + s[0:2]
                return new_s
            
            s_box_aes = pd.read_csv("data/data-aes.csv")

            def Substitute_S_Box(s):
                new_s = ""
                i = 0
                while i < 8:
                    row = int(s[i], 16)
                    i = i+1
                    col = int(s[i], 16)
                    new_s = new_s + s_box_aes.iloc[row][col]
                    i = i+1
                return new_s
            
            def Hex_XOR_8(s1, s2):
                return hex(int(s1, 16) ^ int(s2, 16))[2:].zfill(8)
            
            def XOR_With_RconJ(s, round_num):
                RcJ = ["01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"]
                RconJ = RcJ[round_num - 1] + "00" + "00" + "00"
                
                xor_result = Hex_XOR_8(RconJ, s)
                return xor_result
            
            def G_Function(round_num, g_input):
                after_ls = LS_1_Byte(g_input)
                after_s_box = Substitute_S_Box(after_ls)
                after_xor = XOR_With_RconJ(after_s_box, round_num)
                
                return after_xor
            
            rounds = [1,2,3,4,5,6,7,8,9,10]
            Ws = [w0, w1, w2, w3]
            round_keys = [key]

            for r in rounds:
                this_r_key = ""
                for i in range(4):
                    
                    current_generation = len(Ws) 
                    
                    if (current_generation % 4 == 0):
                        g_f_output = G_Function(r, Ws[-1])
                        new_w = Hex_XOR_8(g_f_output, Ws[-4])
                        
                        Ws.append(new_w)
                        this_r_key = this_r_key + new_w
                    else:
                        
                        new_w = Hex_XOR_8(Ws[-1], Ws[-4])
                        
                        Ws.append(new_w)
                        this_r_key = this_r_key + new_w
                        
                round_keys.append(this_r_key)
            
            with st.expander("Round Keys"):
                round_nums = [f"Round #{i}" for i in range(11)]
                round_keys_values = [round_keys[i] for i in range(11)]

                df = pd.DataFrame({
                    "Round #": round_nums,
                    "Round Key": round_keys_values
                })

                st.table(df)

            def Hex_XOR_32(s1, s2):
                return hex(int(s1, 16) ^ int(s2, 16))[2:].zfill(32)
            round_0_output = Hex_XOR_32(plain_text, round_keys[0])

            def Hex_XOR_32_sec(s1, s2):
                return hex(int(s1, 16) ^ int(s2, 16))[2:].zfill(32)
            round_0_output_sec = Hex_XOR_32_sec(plain_text_sec, round_keys[0])

            def Substitute_S_Box_32(s):
                new_s = ""
                i = 0
                while i < 32:
                    row = int(s[i], 16)
                    i = i+1
                    col = int(s[i], 16)
                    new_s = new_s + s_box_aes.iloc[row][col]
                    i = i+1
                return new_s
            
            def transform_s(s):
                index = 0
            
                transform_s_1 = s[index] + s[index+1] + s[index+8] + s[index+9] + s[index+16] + s[index+17] + s[index+24] + s[index+25]
                index = index + 2 
                transform_s_2 = s[index] + s[index+1] + s[index+8] + s[index+9] + s[index+16] + s[index+17] + s[index+24] + s[index+25]
                index = index + 2
                transform_s_3 = s[index] + s[index+1] + s[index+8] + s[index+9] + s[index+16] + s[index+17] + s[index+24] + s[index+25]
                index = index + 2
                transform_s_4 = s[index] + s[index+1] + s[index+8] + s[index+9] + s[index+16] + s[index+17] + s[index+24] + s[index+25]
                    
                transformed_s_matrix = [transform_s_1, transform_s_2, transform_s_3, transform_s_4]
                
                return transformed_s_matrix
            
            def LS_2_Byte(s):
                new_s = s[4:] + s[0:4]
                return new_s
            
            def LS_3_Byte(s):
                new_s = s[6:] + s[0:6]
                return new_s
            
            def shift_rows(s):
                transformed_s = transform_s(s)
                shifted_s_matrix = [[transformed_s[0]], [LS_1_Byte(transformed_s[1])], [LS_2_Byte(transformed_s[2])], [LS_3_Byte(transformed_s[3])]]
                return shifted_s_matrix

            def bitwise_left(s):
                s = s * 2
                return s

            def bitwise_xor(a, b):
                a = bin(a)[2:].zfill(32)
                b = bin(b)[2:].zfill(32)
                c = ""
                i = 0
                
                while i < 32:
                    if a[i] == b[i]:
                        c = c + "0"
                    else:
                        c = c + "1"
                    i = i + 1
                c = int(c,2)
                return c

            def bitwise_and(a, b):
                a = bin(a)[2:].zfill(32)
                b = bin(b)[2:].zfill(32)
                c = ""
                i = 0
                
                while i < 32:
                    if a[i] == b[i]:
                        if a[i] == "1":
                            c = c+"1"
                        else:
                            c = c+"0"
                    else:
                        c = c+"0"
                    i = i +1
                c = int(c,2)
                return c

            def mpy(x, y):                  
                x = int(x, 2)
                y = int(y, 2)
                
                p = 283             
                m = 0                      
                
                for i in range(8):
                    m = bitwise_left(m)
                    
                    if bitwise_and(m, 256):
                        m = bitwise_xor(m, p)
                        
                    if bitwise_and(y, 128):
                        m = bitwise_xor(m, x)
                        
                    y = bitwise_left(y)
                return m
            def toColumns(s):
                new_s = []
                
                new_s.append(s[0][0][0:2] + s[1][0][0:2] + s[2][0][0:2] + s[3][0][0:2]) 
                new_s.append(s[0][0][2:4] + s[1][0][2:4] + s[2][0][2:4] + s[3][0][2:4]) 
                new_s.append(s[0][0][4:6] + s[1][0][4:6] + s[2][0][4:6] + s[3][0][4:6]) 
                new_s.append(s[0][0][6:8] + s[1][0][6:8] + s[2][0][6:8] + s[3][0][6:8]) 
                
                return new_s
            
            def Hex2Bin(word):
                bin_word = ""
                for i in word:
                    bin_word = bin_word + bin(int(i, 16))[2:].zfill(4)
                return bin_word
            
            def XOR(s1, s2):
                c = ""
                for i in range(8):
                    if s1[i] == s2[i]:
                        c = c + "0"
                    else:
                        c = c + "1"
                return c
            
            def Hex_Multiply(s1, s2):
                s1 = s1[0]

                x1 = mpy(Hex2Bin(s1[0:2]), Hex2Bin(s2[0:2]))
                x2 = mpy(Hex2Bin(s1[2:4]), Hex2Bin(s2[2:4]))
                x3 = mpy(Hex2Bin(s1[4:6]), Hex2Bin(s2[4:6]))
                x4 = mpy(Hex2Bin(s1[6:8]), Hex2Bin(s2[6:8]))

                x1 = bin(x1)[2:].zfill(8)
                x2 = bin(x2)[2:].zfill(8)
                x3 = bin(x3)[2:].zfill(8)
                x4 = bin(x4)[2:].zfill(8)

                x5 = XOR(x1, x2)
                x6 = XOR(x3, x4)
                
                c = XOR(x5, x6)

                c = hex(int(c, 2))[2:].zfill(2)

                return c

            def mix_columns(s):
                s_columns = toColumns(s)
                fixed_matrix = [['02030101'], ['01020301'], ['01010203'], ['03010102']]
                
                mix_column_matrix = [["", "", "", ""], ["", "", "", ""], ["", "", "", ""], ["", "", "", ""]]

                for r in range(4):
                    for c in range(4):
                        mix_column_matrix[r][c] = Hex_Multiply(fixed_matrix[r], s_columns[c])
                return mix_column_matrix
            
            def matrix2norm(s):
                new_s = ""
                for c in range(4):
                    for r in range(4):
                        new_s = new_s + s[r][c]
                return new_s
            
            def makeProperMatrix(s):
                my_m = [["", "", "", ""], ["", "", "", ""], ["", "", "", ""], ["", "", "", ""]]
                for r in range(4):
                    row = s[r][0]
                    my_m[r][0] = row[0:2]
                    my_m[r][1] = row[2:4]
                    my_m[r][2] = row[4:6]
                    my_m[r][3] = row[6:8]

                return my_m
            i = 1

            round_outputs = [round_0_output]
            round_outputs_sec = [round_0_output_sec]
            round_input = round_0_output
            round_input_sec = round_0_output_sec

            while i <= 10:
                s_box_output = Substitute_S_Box_32(round_input)
                s_box_output_sec = Substitute_S_Box_32(round_input_sec)
                shift_rows_output_matrix = shift_rows(s_box_output)
                shift_rows_output_matrix_sec = shift_rows(s_box_output_sec)
              
                if i == 10:
                    mix_columns_output_matrix = makeProperMatrix(shift_rows_output_matrix)
                    mix_columns_output_matrix_sec = makeProperMatrix(shift_rows_output_matrix_sec)
                else:
                    mix_columns_output_matrix = mix_columns(shift_rows_output_matrix)
                    mix_columns_output_matrix_sec = mix_columns(shift_rows_output_matrix_sec)
                
                mix_columns_output_NORMAL = matrix2norm(mix_columns_output_matrix)
                add_round_key_output = Hex_XOR_32(mix_columns_output_NORMAL, round_keys[i])
                mix_columns_output_NORMAL_sec = matrix2norm(mix_columns_output_matrix_sec)
                add_round_key_output_sec = Hex_XOR_32_sec(mix_columns_output_NORMAL_sec, round_keys[i])
                
                round_outputs.append(add_round_key_output)
                round_outputs_sec.append(add_round_key_output_sec)
                round_input = add_round_key_output
                round_input_sec = add_round_key_output_sec

                i = i+1
            
            with st.expander("Round Outputs"):
                round_nums = [f"Round {index}" for index, _ in enumerate(round_outputs)]
                round_outputs_values = round_outputs

                df = pd.DataFrame({
                    "Round #": round_nums,
                    "Round Output": round_outputs_values
                })

                st.table(df)

            with st.expander("Modify Round Outputs"):
                round_nums = [f"Round {index}" for index,
                              _ in enumerate(round_outputs_sec)]
                round_outputs_values_sec = round_outputs_sec

                df = pd.DataFrame({
                    "Round #": round_nums,
                    "Round Output": round_outputs_values_sec
                })

                st.table(df)

            def Hex2Text(hex_string):
                try:
                    return bytes.fromhex(hex_string).decode('utf-8')
                except ValueError as e:
                    return str(e)

            st.markdown("<h5 style='color:cyan'>Encryption</h5>", unsafe_allow_html=True)
            cipher_text = round_outputs[10]
            st.success(f"Cipher Text : {cipher_text}")

            st.markdown("<h5 style='color:cyan'>Decryption</h5>", unsafe_allow_html=True)
            decrypt_text = Hex2Text(plain_text)
            st.success(f"Plain Text : {decrypt_text}")
            
            st.markdown("<h5 style='color:cyan'>Modify Encryption</h5>", unsafe_allow_html=True)
            cipher_text_sec = round_outputs_sec[10]
            st.success(f"Cipher Text : {cipher_text_sec}")

            st.markdown("<h5 style='color:cyan'>Modify Decryption</h5>", unsafe_allow_html=True)
            decrypt_text_sec = Hex2Text(plain_text_sec)
            st.success(f"Plain Text : {decrypt_text_sec}")
            
            def avalanche_effect(original, modified):
                diff = int(original, 16) ^ int(modified, 16)
                return bin(diff).count("1")

            st.markdown("<h5 style='color:cyan'>Avalanche Effect</h5>", unsafe_allow_html=True)
            avalanche_effect_percentage = avalanche_effect(cipher_text, cipher_text_sec)
            st.warning(f"Avalanche Effect : {avalanche_effect_percentage / plain_text_length * 100:.2f}%")

            st.markdown("<h3 style='color:white'>Before Avalanche Effect</h3>", unsafe_allow_html=True)

            def character_error_rate(original, decrypted):
                return sum([1 for o, d in zip(original, decrypted) if o != d]) / max(len(original), len(decrypted)) * 100
            
            st.markdown("<h5 style='color:cyan'>Character Error Rate (CER)</h5>", unsafe_allow_html=True)
            first_character_error_rate_percentage = character_error_rate(Hex2Text(plain_text), decrypt_text)
            second_character_error_rate_percentage = character_error_rate(Hex2Text(plain_text_sec), decrypt_text_sec)
            st.info(f"Character Error Rate (CER) : {(first_character_error_rate_percentage + second_character_error_rate_percentage) / 2:.2f}%")

            def bit_difference(hex1, hex2):
                bin1 = bin(int(hex1, 16))[2:].zfill(len(hex1) * 4)
                bin2 = bin(int(hex2, 16))[2:].zfill(len(hex2) * 4)
                return sum(1 for b1, b2 in zip(bin1, bin2) if b1 != b2) / len(bin1) * 100

            st.markdown("<h5 style='color:cyan'>Bit Error Rate (BER)</h5>", unsafe_allow_html=True)
            first_bit_error_rate_percentage = bit_difference(plain_text, Text2Hex(decrypt_text))
            second_bit_error_rate_percentage = bit_difference(plain_text_sec, Text2Hex(decrypt_text_sec))
            st.info(f"Bit Error Rate (BER) : {(first_bit_error_rate_percentage + second_bit_error_rate_percentage) / 2:.2f}%")
            
            st.markdown("<h3 style='color:white'>After Avalanche Effect</h3>", unsafe_allow_html=True)

            def character_error_rate(original, decrypted):
                return sum([1 for o, d in zip(original, decrypted) if o != d]) / max(len(original), len(decrypted)) * 100
            
            st.markdown("<h5 style='color:cyan'>After Character Error Rate (CER)</h5>", unsafe_allow_html=True)
            character_error_rate_percentage = character_error_rate(Hex2Text(plain_text), Hex2Text(plain_text_sec))
            st.info(f"Character Error Rate (CER) : {character_error_rate_percentage :.2f}%")

            def bit_difference(hex1, hex2):
                bin1 = bin(int(hex1, 16))[2:].zfill(len(hex1) * 4)
                bin2 = bin(int(hex2, 16))[2:].zfill(len(hex2) * 4)
                return sum(1 for b1, b2 in zip(bin1, bin2) if b1 != b2) / len(bin1) * 100

            st.markdown("<h5 style='color:cyan'>After Bit Error Rate (BER)</h5>", unsafe_allow_html=True)
            bit_error_rate_percentage = bit_difference(plain_text, plain_text_sec)
            st.info(f"Bit Error Rate (BER) : {bit_error_rate_percentage:.2f}%")

if _name_ == "_main_":
    main()
