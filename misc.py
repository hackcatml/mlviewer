import re
import struct


def hex_pattern_check(text: str):
    # Memory scan pattern check
    if (pattern := text) == '':
        return "Error: put some pattern"
    else:
        pattern = pattern.replace(' ', '')
        if len(pattern) % 2 != 0 or len(pattern) == 0:
            return "Error: hex pattern length should be 2, 4, 6..."
        # Check hex pattern match regex (negative lookahead)
        # Support mask for the memory scan pattern
        elif re.search(r"(?![0-9a-fA-F?]).", pattern) or re.search(r"^[?]{2}|[?]{2}$", pattern):
            return "Error: invalid hex pattern"
        # Hex pattern check passed, return original text
        return text


def mem_patch_value_check_up(type: str, value: str):
    unsigned_integer_regex = re.compile(r'^\d+$')
    integer_regex = re.compile(r'^-?\d+$')
    float_regex = re.compile(r'^-?\d+(\.\d+)?$')
    error = False
    if type == 'writeU8':
        if unsigned_integer_regex.match(value) and int(value) < 256:
            pass
        else:
            error = True
    elif type == 'writeU16':
        if unsigned_integer_regex.match(value) and int(value) < 65536:
            pass
        else:
            error = True
    elif type == 'writeU32':
        if unsigned_integer_regex.match(value) and int(value) < 4294967296:
            pass
        else:
            error = True
    elif type == 'writeU64':
        if unsigned_integer_regex.match(value) and int(value) < 18446744073709551616:
            pass
        else:
            error = True
    elif type == 'writeInt':
        if integer_regex.match(value) and (-2147483648 <= int(value) < 2147483648):
            pass
        else:
            error = True
    elif type == 'writeFloat':
        if float_regex.match(value):
            pass
        else:
            error = True
    elif type == 'writeDouble':
        if float_regex.match(value):
            pass
        else:
            error = True
    elif type == 'writeUtf8String':
        pass
    elif type == 'writeByteArray':
        result = hex_pattern_check(value)
        if 'Error' in result:
            return result
        else:
            byte_pairs = hex_value_byte_pairs(result)
            byte_array = ["".join(("0x", item)) for item in byte_pairs]
            return byte_array

    if error:
        return 'Error: wrong value'
    else:
        return value


def change_value_to_little_endian_hex(value, option, radix):
    try:
        if isinstance(value, str):
            if option == 'Float' or option == 'Double':
                value = float(value)
            elif option == 'String':
                pass
            else:
                if "." in value:
                    value = int(float(value))
                else:
                    value = int(value, radix)
    except ValueError as e:
        return f"Error: {e}"

    print(f"[misc][change_value_to_little_endian_hex] {value}")
    hex_value = ''
    if option == '1 Byte':
        if -128 <= value < 128:
            hex_value = struct.pack('b', value).hex()
        elif 128 <= value < 256:
            hex_value = struct.pack('B', value).hex()
        else:
            hex_value = 'ff'
    elif option == '2 Bytes':
        if -32768 <= value < 32768:
            hex_value = struct.pack('<h', value).hex()
        elif 32768 <= value < 65536:
            hex_value = struct.pack('<H', value).hex()
        else:
            hex_value = 'ffff'
    elif option == '4 Bytes':
        if -2147483648 <= value < 2147483648:
            hex_value = struct.pack('<i', value).hex()
        elif 2147483648 <= value < 4294967296:
            hex_value = struct.pack('<I', value).hex()
        else:
            hex_value = 'ffffffff'
    elif option == '8 Bytes':
        if -9223372036854775808 <= value < 9223372036854775808:
            hex_value = struct.pack('<q', value).hex()
        elif 9223372036854775808 <= value < 18446744073709551616:
            hex_value = struct.pack('<Q', value).hex()
        else:
            hex_value = 'ffffffffffffffff'
    elif option == 'Int':
        if -2147483648 <= value < 2147483648:
            hex_value = struct.pack('<i', value).hex()
        else:
            hex_value = 'ffffffff'
    elif option == 'Float':
        hex_value = struct.pack('<f', value).hex()
    elif option == 'Double':
        hex_value = struct.pack('<d', value).hex()
    elif option == 'String':
        hex_value = bytes(value, 'utf-8').hex()

    return hex_value


def hex_value_byte_pairs(hex_value: str):
    hex_value = hex_value.replace(' ', '')
    # print(f"[misc] hex_value: {hex_value}")
    # Split the hex string into two-character chunks (each byte)
    byte_pairs = [hex_value[i:i + 2] for i in range(0, len(hex_value), 2)]
    print(f"[misc] byte_pairs: {byte_pairs}")
    return byte_pairs


def change_little_endian_hex_to_value(hex_value: str, option: str):
    byte_pairs = hex_value_byte_pairs(hex_value)
    print(f"[misc][change_little_endian_hex_to_value] {byte_pairs}")
    value = ''
    if option == '1 Byte' or option == '2 Bytes' or option == '4 Bytes' or option == '8 Bytes':
        reversed_bytes = "".join(reversed(byte_pairs))
        try:
            value = int(reversed_bytes, 16)
        except Exception as e:
            return f"Error: {e}"
    elif option == 'Int':
        try:
            byte_pairs = bytes.fromhex("".join(byte_pairs))
            value = struct.unpack('<i', byte_pairs[:4])[0]
        except Exception as e:
            return f"Error: {e}"
    elif option == 'Float' or option == 'Double':
        try:
            byte_pairs = bytes.fromhex("".join(byte_pairs))
            if option == 'Float':
                value = struct.unpack('<f', byte_pairs[:4])[0]
            else:
                value = struct.unpack('<d', byte_pairs[:8])[0]
        except Exception as e:
            return f"Error: {e}"
    elif option == 'String':
        value = bytes.fromhex(hex_value).decode("utf-8")
    elif option == 'Array of Bytes':
        value = hex_value

    return str(value)


def generate_hex_pattern_for_rounded_float_double(value, option):
    try:
        if type(value) is str:
            value = float(value)
    except ValueError as e:
        return f"Error: {e}"

    # Determine the integer to which the value rounds
    rounded_value = round(value)

    # Define the rounding range for this integer
    lower_bound = rounded_value - 0.5
    upper_bound = rounded_value + 0.4

    # Convert the bounds to hex representations
    lower_bound_hex = change_value_to_little_endian_hex(lower_bound, option, 10)
    upper_bound_hex = change_value_to_little_endian_hex(upper_bound, option, 10)

    # Compare the lower and upper bound hex representations to create the pattern
    hex_pattern = []
    for lb_byte, ub_byte in zip(lower_bound_hex, upper_bound_hex):
        if lb_byte == ub_byte:
            hex_pattern.append(lb_byte)  # Keep the common byte
        else:
            hex_pattern.append('?')  # Use '?' for varying bytes

    # Group pattern into pairs (for readability like "40 56 ?? ?? ?? ?? ?? ??")
    pattern = " ".join("".join(hex_pattern[i:i + 2]) for i in range(0, len(hex_pattern), 2))
    pattern = pattern.replace("00", "??")
    pattern = pattern.replace("??", "").strip()

    return pattern


def hex_to_bytes(hex_code):
    # Convert the hex string to bytes without reversing the order
    return bytes.fromhex(hex_code)


def hex_code_read_as_u8(hex_code):
    value_bytes = hex_to_bytes(hex_code)
    return struct.unpack('B', value_bytes[:1])[0]  # Read the first byte (u8)


def hex_code_read_as_u16(hex_code):
    value_bytes = hex_to_bytes(hex_code)
    return struct.unpack('<H', value_bytes[:2])[0]  # Read 2 bytes starting from the 2nd byte (u16)


def hex_code_read_as_u32(hex_code):
    value_bytes = hex_to_bytes(hex_code)
    return struct.unpack('<I', value_bytes[:4])[0]  # Read 4 bytes starting from the 2nd byte (u32)


def hex_code_read_as_u64(hex_code):
    value_bytes = hex_to_bytes(hex_code)
    return struct.unpack('<Q', value_bytes[:8])[0]  # Read 8 bytes starting from the 2nd byte (u64)


def hex_code_read_as_int(hex_code):
    value_bytes = hex_to_bytes(hex_code)
    return struct.unpack('<i', value_bytes[:4])[0]  # Read 4 bytes from the beginning for int


def hex_code_read_as_float(hex_code):
    value_bytes = hex_to_bytes(hex_code)
    return struct.unpack('<f', value_bytes[:4])[0]  # Read 4 bytes from the beginning for float


def hex_code_read_as_double(hex_code):
    value_bytes = hex_to_bytes(hex_code)
    return struct.unpack('<d', value_bytes[:8])[0]  # Read 8 bytes from the beginning for double


def number_to_ordinal(n):
    n = int(n)  # Ensure it's an integer
    if 10 <= n % 100 <= 20:  # Special case for '11th', '12th', '13th', etc.
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
    return f"{n}{suffix}"
