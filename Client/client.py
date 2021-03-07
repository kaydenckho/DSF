import rsa
import os, sys
import hashlib
import getpass
import requests
from Crypto.Cipher import AES

requests.packages.urllib3.disable_warnings() 
client_repo_folder_name = "client_repository"
certificate_repo_filename = "certificate.dat"
private_key_repo_filename = "private_key.dat"
file_archival_repo_folder_name = "Document Archival"

client_repo_folder = os.path.join(os.getcwd(), client_repo_folder_name)
file_archival_repo_folder = os.path.join(client_repo_folder, file_archival_repo_folder_name)

server_domain = "https://192.168.1.102:5678/"

def get_credentials():
	# input credentials
	userid = input("User ID: ").upper()
	while userid == "":
		print("Empty userid. Please enter again.")
		userid = input("User ID: ")
	password = getpass.getpass().upper()
	while password == "":
		print("Empty password. Please enter again.")
		password = getpass.getpass()

	# generate sha256 hashes for password
	userid_hash = str(hashlib.sha256(userid.encode()).hexdigest())
	password_hash = str(hashlib.sha256(password.encode()).hexdigest())
	return userid_hash, password_hash

def generate_keys():
	# generate RSA key pairs
	pubkey, privkey = rsa.newkeys(1024)
	certificate_public = str({"n":pubkey.n, "e":pubkey.e})
	certificate_private = str({"n":privkey.n, "e":privkey.e, "d":privkey.d, "p":privkey.p, "q":privkey.q})
	return certificate_public, certificate_private

def get_request(url):
	response = requests.get(url, verify=False)
	return response

def post_request(url, data):
	response = requests.post(url, files=data, verify=False)
	return response

def menu(userid, password):

	userid_hash = userid
	password_hash = password

	def upload():
		file_path = input("File Path: ")
		if not (os.path.exists(file_path) and os.path.isfile(file_path)):
			print("!!! File Not Found !!!")
			menu(userid_hash, password_hash)
			return
		destination = input("Destination: ").upper()
		destination_hash = str(hashlib.sha256(destination.encode()).hexdigest())
		file_path = file_path.replace('"','')
		filename = os.path.basename(file_path)
		# load private key of sender
		with open(os.path.join(client_repo_folder, private_key_repo_filename), "r") as f:
			priv_key_file = eval(f.read())
		priv_key = rsa.PrivateKey(**priv_key_file)

		with open(file_path, "rb") as f:
			file_bytes = f.read()
		signature = rsa.sign(file_bytes, priv_key, 'SHA-256')

		# load public key of receiver
		with open(os.path.join(client_repo_folder, certificate_repo_filename), "r") as f:
			pub_key_file = eval(f.read())
		if (pub_key_file.get(destination_hash) != None and destination_hash != userid_hash):
			# generate designated verifier signature
			random_bits = rsa.randnum.read_random_bits(128)
			aes_key = AES.new(random_bits, AES.MODE_EAX)
			nonce = aes_key.nonce
			signature_enc, tag = aes_key.encrypt_and_digest(signature)

			# encrypt AES-128 key using RSA public key
			pub_key_dest = rsa.PublicKey(**pub_key_file.get(destination_hash))
			aes_key_enc = rsa.encrypt(random_bits, pub_key_dest)
			signature = str({aes_key_enc, nonce, signature_enc, tag})
			# generate designated verifier signature

			url = server_domain + 'upload_file'
			data = {
			"username": (None, userid_hash),
			"password": (None, password_hash),
			"content": (filename, file_bytes),
			"signature": ('signature_file', signature),
			"destination": (None, destination_hash)
			}
			try:
				response = post_request(url, data)
			except:
				print("!!! Network error !!!")
				menu(userid_hash, password_hash)
				return
			response_json = response.json()
			if response_json['statusCode'] == 'OK':
				if response_json['description'] == 'Uploaded':
					print("Uploaded Successfully.")
				if response_json['description'] == 'Invalid Destination':
					print("!!! Invalid Destination !!!")
				if response_json['description'] == 'Server Error':
					print("!!! Server Error !!!")
				menu(userid_hash, password_hash)
				return
			else:
				print("!!! Authentication Failed !!!")
				login()
				return
		else:
			print("!!! Invalid Destination !!!")
			menu(userid_hash, password_hash)

		
	def download():
		a = 0

	def update_cert():

		certificate_public, certificate_private = generate_keys()

		url = server_domain + 'update_cert'
		data = {
		"username": (None, userid_hash),
		"password": (None, password_hash),
		"certificate": (None, certificate_public)
		}
		try:
			response = post_request(url, data)
		except:
			print("!!! Network error !!!")
			menu()
			return
		response_json = response.json()
		if response_json['statusCode'] == 'OK':
			if response_json['description'] == 'Updated':
				with open("Client Repository/Private Key.dat", "w") as f:
					data = f.write(str(certificate_private))
				print("Updated Successfully.")
			menu(userid_hash, password_hash)
			return
		else:
			print("!!! Authentication Failed !!!")
			login()

	def verify():
		a = 0

	def exit():
		sys.exit()

	option = input("\n--- Digital Signature API ---\n\t--- Menu ---\n(1)Upload File\n(2)Download File\n(3)Update Certificate\n(4)Verify Signature File\n(5)Exit\n\nPlease enter a number(1-5): ")
	functions = {'1':upload, '2':download, '3':update_cert, '4':verify, '5':exit}
	while not option in functions.keys():
		print("!!! Invalid Input !!!")
		option = input("\n--- Digital Signature API ---\n\t--- Menu ---\n(1)Upload File\n(2)Download File\n(3)Update Certificate\n(4)Verify Signature File\n(5)Exit\n\nPlease enter a number(1-5): ")
	else:
		functions[option]()

def login():
	print("\n--- Digital Signature API ---\n\t--- Login ---\n")
	userid_hash, password_hash = get_credentials()
	# initialize local repository and store key
	if not os.path.exists(client_repo_folder):
		os.mkdir(client_repo_folder)
	if not os.path.exists(file_archival_repo_folder):
		os.mkdir(file_archival_repo_folder)
	if not os.path.exists(os.path.join(client_repo_folder, private_key_repo_filename)):
		certificate_public, certificate_private = generate_keys()
		with open(os.path.join(client_repo_folder, private_key_repo_filename), "w+") as f:
			f.write(certificate_private)
	else:
		with open(os.path.join(client_repo_folder, private_key_repo_filename), "r") as f:
			priv_key_file = eval(f.read())
		certificate_public = str({'n':priv_key_file['n'], 'e':priv_key_file['e']})

	url = server_domain + 'login'
	data = {
	"username": (None, userid_hash),
	"password": (None, password_hash),
	"certificate": (None, certificate_public)
	}
	try:
		response = post_request(url, data)
	except:
		print("!!! Network error !!!")
		login()
		return
	response_json = response.json()
	if response_json['statusCode'] == 'OK':
		if response_json['description'] == 'Invalid Certificate':
			print("!!! Invalid Certificate !!!")
			login()
			return
		else:
			url = server_domain + 'get_certificates'
			response = get_request(url)
			certificate_list = eval(response.text)
			key_list = list(certificate_list.keys())
			for i in range(len(certificate_list)):
				certificate_list[key_list[i]] = eval(certificate_list.get(key_list[i]))
			with open(os.path.join(client_repo_folder, certificate_repo_filename), "w+") as f:
					f.write(str(certificate_list))
			menu(userid_hash, password_hash)
			return
	elif response_json['statusCode'] == 'FAIL':
		print("!!! Authentication Failed !!!")
	login()

if __name__ == '__main__':
	login()