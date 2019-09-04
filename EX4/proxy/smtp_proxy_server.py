#!/usr/bin/python

import socket		# for sokets
import sys			# for exit
import select		# for select
from proxy_server_utils import *


SMTP_PROXY_HOST_IN = '10.0.1.3'
SMTP_PROXY_PORT_IN = 8006
MAX_PACKET_SIZE = 4096


def main():

	try:
		s_in = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error, msg:
		print 'Failed to create IN socket. Error code: ' + str(msg[0]) + ' , Error message: ' + msg[1]
		sys.exit()
	print 'IN Socket created'

	try:
		s_in.bind((SMTP_PROXY_HOST_IN, SMTP_PROXY_PORT_IN))
		#s_in.bind(('10.1.1.3', 8006))
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
					frame = conn_in.recv(MAX_PACKET_SIZE)
					if frame:
						print 'PROXY - s_in'
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
					print 'PROXY - s_out'
					frame = s_out.recv(MAX_PACKET_SIZE)
					if frame:
						print frame
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
