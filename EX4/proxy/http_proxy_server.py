#!/usr/bin/python

import socket		# for sokets
import sys			# for exit
import select		# for select
from proxy_server_utils import *


HTTP_PROXY_HOST_IN = '10.0.1.3'
HTTP_PROXY_PORT_IN = 8007
MAX_PACKET_SIZE = 4096


def main():

	try:
		s_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error, msg:
		print 'Failed to create IN socket. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	print 'IN Socket created'

	try:
		s_in.bind((HTTP_PROXY_HOST_IN, HTTP_PROXY_PORT_IN))
	except socket.error, msg:
		print 'Bind failed. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	print 'IN Socket bind complete'

	s_in.listen(10)
	print 'IN Socket now listening'

	while True:
		print '********************************************************'
		conn_in, addr = s_in.accept()
		print 'IN Socket connected with ' + addr[0] + ':' + str(addr[1])
		
		try:
			# create an AF_INET, STREAM socket (TCP)
			s_out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except socket.error, msg:
			print 'Failed to create OUT socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1]
			s_in.close()
			sys.exit()
		print 'OUT Socket Created'
		
		# Connect to remote server
		dst_host, dst_port = get_dst_host_ip(addr[0], addr[1])
		s_out.connect((dst_host , int(dst_port)))
		print 'OUT Socket connected with ' + dst_host + ':' + dst_port		
		inputs = [conn_in, s_out]
		outputs = []
		conn_active = 1
		print '++++++++++++++++++++++++++++'
		while conn_active:
			#print 'PROXY - before select'
			readable, writable, exceptional = select.select(inputs, outputs, inputs)
			#print 'PROXY - after select'
			for s in readable:
				if s == conn_in:
					#print 'PROXY - IN S_IN'
					frame = conn_in.recv(MAX_PACKET_SIZE)
					if frame:
						print frame
						if (check_if_C_code(frame)):
							buf = '' + str(IP2Int(addr[0])) + ' ' + str(addr[1])
							close_connection_in_fw(buf)
							conn_in.shutdown(socket.SHUT_RDWR)
							conn_active = 0
							readable.remove(conn_in)
							print 'PROXY - blocked outgoing E-mail with suspected C code'
							continue
						s_out.sendall(frame)
						readable.remove(conn_in)
					else:
						readable.remove(conn_in)
						conn_in.shutdown(socket.SHUT_RD)
						conn_active = 0
						continue
				if s == s_out:
					#print 'PROXY - IN S_OUT'
					frame = s_out.recv(MAX_PACKET_SIZE)
					if frame:
						#print frame
						bin_frame = bytearray(frame)
						#magic number of mkv files is 1A 45 DF A3
						if bin_frame[0] == 49 and bin_frame[1] == 65 and bin_frame[2] == 32 and \
						bin_frame[3] == 52 and bin_frame[4] == 53 and bin_frame[5] == 32 and \
						bin_frame[6] == 68 and bin_frame[4] == 70 and bin_frame[5] == 32 and \
						bin_frame[6] == 65 and bin_frame[4] == 51:
							buf = '' + str(IP2Int(addr[0])) + ' ' + str(addr[1])
							close_connection_in_fw(buf)
							s_out.shutdown(socket.SHUT_RDWR)
							conn_active = 0
							readable.remove(s_out)
							print 'PROXY - blocked mkv file'
							continue	
						len_index = frame.find('Content-Length', 0, len(frame))
						if len_index == -1:
							s_out.shutdown(socket.SHUT_RD)
							conn_active = 0
							readable.remove(s_out)
							print 'PROXY - blocked data with no content length'
							continue
						len_index += len('Content-Length: ')
						con_len = ' '
						for i in range(0, 5):
							if (frame[len_index+i: len_index+i+1]).isdigit():
								con_len += frame[len_index+i: len_index+i+1]
							else:
								break
						if int(con_len) > 2000:
							#magic number of MS docs
							if bin_frame[0] == 68 and bin_frame[1] == 48 and bin_frame[2] == 32 and \
							bin_frame[3] == 67 and bin_frame[4] == 70 and bin_frame[5] == 32 and \
							bin_frame[6] == 49 and bin_frame[7] == 49 and bin_frame[8] == 32 and \
							bin_frame[9] == 69 and bin_frame[10] == 48 and bin_frame[11] == 32 and \
							bin_frame[12] == 65 and bin_frame[13] == 49 and bin_frame[14] == 32 and \
							bin_frame[15] == 66 and bin_frame[16] == 49 and bin_frame[17] == 32 and \
							bin_frame[18] == 49 and bin_frame[19] == 65 and bin_frame[20] == 32 and \
							bin_frame[21] == 69 and bin_frame[22] == 49:
								buf = '' + str(IP2Int(addr[0])) + ' ' + str(addr[1])
								close_connection_in_fw(buf)
								s_out.shutdown(socket.SHUT_RDWR)
								conn_active = 0
								readable.remove(s_out)
								print 'PROXY - blocked word dock'
								continue	
						conn_in.sendall(frame)
						readable.remove(s_out)
					else:
						readable.remove(s_out)
						s_out.shutdown(socket.SHUT_RD)
						conn_active = 0
						continue
		print 'PROXY - connection with - ' + dst_host + ':' + dst_port + ' - is done'
		s_out.close()
		conn_in.shutdown(socket.SHUT_RDWR)
		conn_in.close()

if __name__ == "__main__":
	main()
