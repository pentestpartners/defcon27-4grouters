#!/usr/bin/python

import sys
import re

import os.path

import argparse
import binascii

from termcolor import colored

from Crypto.Cipher import AES

DEBUG_ON = True

def debug_log(string):
	if DEBUG_ON:
		print colored("[DBG] ", "white", attrs=["bold"]) + string

def log(string):
	print colored("[LOG] ", "green", attrs=["bold"]) + string

def dexor(text, key):
	ret = list(text)
	mod = len(key)
	for index, char in enumerate(ret):
		ret[index] = chr(ord(char) ^ ord(key[index % mod]))
	return "".join(ret)

def substring_indexes(substring, string):
	last_found = -1  # Begin at -1 so the next position to search from is 0
	while True:
		last_found = string.find(substring, last_found + 1)
		if last_found == -1:  
			break  # All occurrences have been found
		yield last_found

def hexdump_head(string, howmanylines):
	shorterstring = string[0:howmanylines*16]
	debug_log("hexdumping " + str(howmanylines) + " lines")
	hexdump(shorterstring)

def hexdump(src, length=16, sep='.'):
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
	lines = []
	for c in xrange(0, len(src), length):
		chars = src[c:c+length]
		hex = ' '.join(["%02x" % ord(x) for x in chars])
		if len(hex) > 24:
			hex = "%s %s" % (hex[:24], hex[24:])
		printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
		lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printable))
	return ''.join(lines)

def parse_header(header):
	if (len(header) != 0x190):
		return None
	else:
		segment_type = header[0x10c:0x110]
		segment_product = header[0x110:0x114]
		segment_size = int(binascii.hexlify(header[0x114:0x118]), 16)
		segment_unk = header[0x118:0x11c]
		segment_version = header[0x11c:0x160].rstrip()
		return segment_type, segment_product, segment_size, segment_unk, segment_version

def length_from_header(header):
	return int(binascii.hexlify(header[0x114:0x118]), 16)

def type_from_header(header):
		return header[0x10c:0x110]

def nn(number):
	number = str(number)
	if len(number) == 1:
		return "0" + number
	else:
		return number

def split_key(key, padding, index):
	final_key = ""

parser = argparse.ArgumentParser()
parser.add_argument('filename')
args = parser.parse_args()

firmware_file = args.filename
firmware_file = open(firmware_file, "rb")

file_name = os.path.abspath(args.filename)
singlename = os.path.split(file_name)[1]
log("using file " + singlename)

this_dir = os.path.dirname(os.path.realpath(__file__))
firmware_dirname = "__" + os.path.split(file_name)[1]

firmware_dir = os.path.join(this_dir, firmware_dirname)

if not os.path.exists(firmware_dir):
	os.makedirs(firmware_dir)

subsection_dir = os.path.join(firmware_dir, "_subsections")

if not os.path.exists(subsection_dir):
	os.makedirs(subsection_dir)

aes_key 	= ""

telltale_sign = "\x80\x40\x4C\x21\x51\x9B\xFD\xC5\xCD\xFF\x2E\xD3\x66\x0B\x8F\x6E"

key_32 		= ''
key_padding = ''

just_headers_filename = os.path.join(firmware_dir, "_justheaders_hexdump.bin")
just_headers_buffer = ""

full_decrypted_filename = os.path.join(firmware_dir, "_decrypted.bin")
full_decrypted_file = ""

global_counter = 0

#log("opening file...")
firmware = firmware_file.read()
file_total_size = len(firmware)
firmware_file.close()

log("file is " + hex(file_total_size) + " long")

aes = AES.new(aes_key, AES.MODE_ECB, "")

# firmware headers always seem to be 0x190 long
header_size = 0x190

firmware_header = firmware[0:header_size]

fwhead_decd = aes.decrypt(firmware_header)
just_headers_buffer += "0x0 " + "-"*32 + "\n"
just_headers_buffer += hexdump(fwhead_decd)

full_decrypted_file += fwhead_decd

main_header_filename = os.path.join(subsection_dir, nn(global_counter) + "_0x0-" + hex(header_size) + ".dec.bin")
with open(main_header_filename, "wb") as f:
	f.write(fwhead_decd)

global_counter += 1

parts = list(map(''.join, zip(*[iter(fwhead_decd)]*16)))
chunk_index = {}

i = 0
for line in parts:
	if line[12:17] == "BASE":
		chunk_index[i] = {}
		chunk_index[i]["number"] = i
		chunk_index[i]["start"] = int(binascii.hexlify(line[4:8]), 16)
		chunk_index[i]["length"] = int(binascii.hexlify(line[8:12]), 16)
		chunk_index[i]["end"] = chunk_index[i]["start"] + chunk_index[i]["length"]
		log("chunk start: " + hex(chunk_index[i]["start"]) + ", length " + hex(chunk_index[i]["length"]) + ", end " + hex(chunk_index[i]["end"]))
		
		key_mod = (chunk_index[i]["length"]-header_size)%32 # calc key shift from mod 32 of the data part of the chunk

		debug_log("(len-header % 32: " + str((chunk_index[i]["length"]-0x190)%32) + "?)")

		key_end = 32 - key_mod

		pad_front = key_padding[key_end::]
		pad_end = key_padding[0:key_end]

		debug_log("key start: " + binascii.hexlify(pad_front) + ", key end: " + binascii.hexlify(pad_end))
		chunk_index[i]["key"] = pad_front + key_32 + pad_end

		i += 1

for chunk in chunk_index.values():
	number = str(chunk["number"])
	this_chunk = firmware[chunk["start"]:chunk["end"]]

	debug_log("starting chunk " + number + "_" + hex(chunk["start"]) + "-" + hex(chunk["end"]))

	header_contents = this_chunk[0:header_size]

	dec_header = aes.decrypt(header_contents)
	main_type = type_from_header(dec_header)

	log("MAIN TYPE: " + main_type)
	just_headers_buffer += hex(chunk["start"]) + " " + "-"*32 + "\n"
	just_headers_buffer += hexdump(dec_header)

	full_decrypted_file += dec_header

	main_header_filename = os.path.join(subsection_dir, nn(global_counter) + "_" + main_type + ".dec.bin")
	with open(main_header_filename, "wb") as f:
		f.write(dec_header)

	global_counter += 1

	body_contents = this_chunk[header_size::]

	key = chunk["key"]

	log("decrypting chunk body...")
	dec_body = dexor(body_contents, key)

	if telltale_sign in dec_body:
		debug_log("\tmore encrypted stuff in the body!!!")
		
		telltale_indexes = []
		for i in substring_indexes(telltale_sign, dec_body):
			telltale_indexes.append(i)

		# take the first subheader index as the starting point
		current_subheader_base = telltale_indexes[0]
		current_subheader_end = current_subheader_base + header_size

		subheaders_list = [current_subheader_base]

		# wherever the initial new encrypted header is found, we should 
		# write the initial chunk body to the dec firmware file anyway
		dec_initial_body = dec_body[0:current_subheader_base]
		full_decrypted_file += dec_initial_body

		for i in telltale_indexes:
			if (i >= current_subheader_end):
				current_subheader_base = i
				current_subheader_end = current_subheader_base + header_size
				subheaders_list.append(current_subheader_base)

		for subheader_base in subheaders_list:
			
			subheader_contents = dec_body[subheader_base:subheader_base+header_size]
			dec_subheader = aes.decrypt(subheader_contents)
			just_headers_buffer += hex(chunk["start"]+subheader_base) + " " + "-"*32 + "\n"
			just_headers_buffer += hexdump(dec_subheader)
			full_decrypted_file += dec_subheader

			subchunk_len = length_from_header(dec_subheader)
			sub_type = type_from_header(dec_subheader)

			debug_log("\tsub-chunk header at " + hex(subheader_base) + ", lenth: " + hex(subchunk_len))
			log("\tSUB TYPE: " + sub_type)


			subchunk_body_start = subheader_base + 0x190
			subchunk_body_end = subchunk_body_start + subchunk_len

			subchunk_body = dec_body[subchunk_body_start:subchunk_body_end]

			dec_subheader_filename = os.path.join(subsection_dir, nn(global_counter) + "_" + main_type + "_" + sub_type + ".dec.bin")

			with open(dec_subheader_filename, "wb") as f:
				debug_log("writing " + dec_subheader_filename)
				f.write(dec_subheader)

			global_counter += 1

			dec_subchunk_filename = os.path.join(subsection_dir, nn(global_counter) + "_" + main_type + "_" + sub_type + ".dec.bin")


			with open(dec_subchunk_filename, "wb") as f:
				debug_log("writing " + dec_subchunk_filename)
				f.write(subchunk_body)

			global_counter += 1

			full_decrypted_file += subchunk_body
		

	else:
		full_decrypted_file += dec_body

		dec_chunk_filename = os.path.join(subsection_dir, nn(global_counter) + "_" + main_type + ".dec.bin")

		# start writing the decrypted stuff
		log("writing decrypted chunk to " + dec_chunk_filename)
		with open(dec_chunk_filename, "wb") as f:
			f.write(dec_body)

		global_counter += 1

log("writing just headers to " + just_headers_filename)
with open(just_headers_filename, "wb") as f:
	f.write(just_headers_buffer)

log("writing full decrypted file to " + full_decrypted_filename)
with open(full_decrypted_filename, "wb") as f:
	f.write(full_decrypted_file)

