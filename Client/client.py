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
file_list_repo_filename = "file_list.dat"
file_archival_repo_folder_name = "Document Archival"
signature_archival_repo_folder_name = "Signature Archival"

client_repo_folder = os.path.join(os.getcwd(), client_repo_folder_name)
file_archival_repo_folder = os.path.join(client_repo_folder, file_archival_repo_folder_name)
signature_archival_repo_folder = os.path.join(file_archival_repo_folder, signature_archival_repo_folder_name)

server_domain = "https://192.168.1.102:5678/"

# utility functions
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
	password_hash = str(hashlib.sha256(password.encode()).hexdigest())
	return userid, password_hash

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
# utility functions

def menu(userid, password):

	userid = userid
	password_hash = password

	def upload():
		file_path = input("File Path: ")
		file_path = file_path.replace('"','')
		if not (os.path.exists(file_path) and os.path.isfile(file_path)):
			print("!!! File Not Found !!!")
			menu(userid, password_hash)
			return
		destination = input("Destination: ").upper()
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
		if (pub_key_file.get(destination) != None and destination != userid):
			# generate designated verifier signature
			random_bits = rsa.randnum.read_random_bits(128)
			aes_key = AES.new(random_bits, AES.MODE_EAX)
			nonce = aes_key.nonce
			signature_enc, tag = aes_key.encrypt_and_digest(signature)

			# encrypt AES-128 key using RSA public key
			pub_key_dest = rsa.PublicKey(**pub_key_file.get(destination))
			aes_key_enc = rsa.encrypt(random_bits, pub_key_dest)
			signature = str([aes_key_enc, nonce, signature_enc, tag])
			# generate designated verifier signature

			url = server_domain + 'upload_file'
			data = {
			"username": (None, userid),
			"password": (None, password_hash),
			"content": (filename, file_bytes),
			"signature": ('signature_file', signature),
			"destination": (None, destination)
			}
			try:
				response = post_request(url, data)
			except:
				print("!!! Network error !!!")
				menu(userid, password_hash)
				return
			response_json = response.json()
			if response_json['statusCode'] == 'OK':
				if response_json['description'] == 'Uploaded':
					print("Uploaded Successfully.")
				if response_json['description'] == 'Invalid Destination':
					print("!!! Invalid Destination !!!")
				if response_json['description'] == 'Server Error':
					print("!!! Server Error !!!")
				menu(userid, password_hash)
				return
			else:
				print("!!! Authentication Failed !!!")
				login()
				return
		else:
			print("!!! Invalid Destination !!!")
			menu(userid, password_hash)

		
	def download():
		url = server_domain + 'get_file_list'
		data = {
		"username": (None, userid),
		}
		try:
			response = post_request(url, data)
		except:
			print("!!! Network error !!!")
			menu(userid, password_hash)
			return
		response_json = response.json()
		if len(response_json)>0:
			file_list_dict = {}
			for value in response_json.values():
				file_list_dict[value[0]] = value[1]
			with open(os.path.join(client_repo_folder, file_list_repo_filename), "w") as f:
				f.write(str(file_list_dict))
			print("List of available files:")
			col_width = max(len(item) for row in response_json.values() for item in row) + 5
			print("FileID".ljust(10), "Filename".ljust(col_width), "Sender")
			for fileID, metadata in response_json.items():
				print("%s"%fileID.ljust(10), "%s"%metadata[0].ljust(col_width), "%s"%metadata[1])
			user_input = input("Please enter the <FileID> of the file you want to download:\n(Enter \"-all\" to download all files.)\n")
			# Input validation
			while not(user_input == "-all" or (user_input in response_json.keys())):
				print("Invalid Input")
				user_input = input("Please enter the <FileID> of the file you want to download:\n(Enter \"-all\" to download all files.)\n")
			else:
				url1 = server_domain + 'download_file'
				url2 = server_domain + 'download_signature'
				if not user_input == "-all":
					data = {
					"FID": (None, eval(user_input))
					}
					try:
						response1 = post_request(url1, data)
						response2 = post_request(url2, data)
					except:
						print("!!! Network error !!!")
						menu(userid, password_hash)
						return
					json_data = eval(response1.headers["Json"])
					if (json_data['statusCode']=='OK' and json_data['description']=="Downloaded file"):
						filename = json_data['filename']
						file_content = response1.content
						with open(os.path.join(file_archival_repo_folder,filename),"wb+") as f:
							f.write(file_content)
					json_data = eval(response2.headers["Json"])
					if (json_data['statusCode']=='OK' and json_data['description']=="Downloaded signature"):
						filename = json_data['filename']
						file_content = response2.content
						signature_filename = filename + ".signature"
						with open(os.path.join(signature_archival_repo_folder,signature_filename),"wb+") as f:
							f.write(file_content)
					print(filename + " was downloaded successfully.")
				else:
					for fileID in response_json.keys():
						data = {
						"FID": (None, eval(fileID))
						}
						try:
							response1 = post_request(url1, data)
							response2 = post_request(url2, data)
						except:
							print("!!! Network error !!!")
							menu(userid, password_hash)
							return
						json_data = eval(response1.headers["Json"])
						if (json_data['statusCode']=='OK' and json_data['description']=="Downloaded file"):
							filename = json_data['filename']
							file_content = response1.content
							with open(os.path.join(file_archival_repo_folder,filename),"wb") as f:
								f.write(file_content)
						json_data = eval(response2.headers["Json"])
						if (json_data['statusCode']=='OK' and json_data['description']=="Downloaded signature"):
							filename = json_data['filename']
							file_content = response2.content
							signature_filename = filename + ".signature"
							with open(os.path.join(signature_archival_repo_folder,signature_filename),"wb") as f:
								f.write(file_content)
					print("All files were downloaded successfully.")
		else:
			print("There is no available file.")
		menu(userid, password_hash)

	def update_cert():
		certificate_public, certificate_private = generate_keys()

		url = server_domain + 'update_cert'
		data = {
		"username": (None, userid),
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
			menu(userid, password_hash)
			return
		else:
			print("!!! Authentication Failed !!!")
			login()

	def verify():
		file_path = input("File Path: ")
		file_path = file_path.replace('"','')
		if not (os.path.exists(file_path) and os.path.isfile(file_path)):
			print("!!! File Not Found !!!")
			menu(userid, password_hash)
			return
		filename = os.path.basename(file_path)

		# OBTAIN CERTIFICATE
		if not (os.path.exists(os.path.join(client_repo_folder, file_list_repo_filename))):
			print("!!! Missing File List !!!")
			menu(userid, password_hash)
			return
		else:
			with open(os.path.join(client_repo_folder, file_list_repo_filename), "r") as f:
				file_list = eval(f.read())
			if file_list.get(filename) != None:
				sender = file_list.get(filename)
			else:
				print("!!! File not downloaded using this API !!!")
			with open(os.path.join(client_repo_folder, certificate_repo_filename), "r") as f:
				pub_key_file = eval(f.read())
			if pub_key_file.get(sender) != None:
				pub_key_params = pub_key_file.get(sender)
				pub_key = rsa.PublicKey(**pub_key_params)
			else:
				print("!!! Obtain Certificate Failed !!!")
		# OBTAIN CERTIFICATE

		# OBTAIN & DECRYPT SIGNATURE
		signature_filename = filename + ".signature"
		if not (os.path.exists(os.path.join(client_repo_folder, private_key_repo_filename))):
			print("!!! Missing private key file !!!")
			menu(userid, password_hash)
			return
		else:
			with open(os.path.join(client_repo_folder, private_key_repo_filename), "r") as f:
				priv_key_params = eval(f.read())

		if not (os.path.exists(os.path.join(signature_archival_repo_folder, signature_filename))):
			print("!!! Corresponding Signature Not Found !!!")
			menu(userid, password_hash)
			return
		else:
			with open(os.path.join(signature_archival_repo_folder, signature_filename), "r") as f:
				signature_raw = eval(f.read())
			aes_key_enc, nonce, signature_enc, tag = signature_raw
			priv_key = rsa.PrivateKey(**priv_key_params)
			try:
				aes_key = rsa.decrypt(aes_key_enc, priv_key)
			except rsa.pkcs1.DecryptionError:
				print("!!! AES Key Decryption Error !!!")
			try:
				cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
				signature = cipher.decrypt_and_verify(signature_enc, tag)
			except:
				print("!!! Signature Decryption Error !!!")
		# OBTAIN & DECRYPT SIGNATURE

		# VERIFY SIGNATURE
		with open(os.path.join(file_archival_repo_folder, filename), "rb") as f:
			try:
				rsa.verify(f, signature, pub_key)
				print("This file is authentic.")
			except rsa.pkcs1.VerificationError:
				print("!!! This file was modified !!!")
		menu(userid, password_hash)
		# VERIFY SIGNATURE

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
	userid, password_hash = get_credentials()
	# initialize local repository and store key
	if not os.path.exists(client_repo_folder):
		os.mkdir(client_repo_folder)
	if not os.path.exists(file_archival_repo_folder):
		os.mkdir(file_archival_repo_folder)
	if not os.path.exists(signature_archival_repo_folder):
		os.mkdir(signature_archival_repo_folder)
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
	"username": (None, userid),
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
			menu(userid, password_hash)
			return
	elif response_json['statusCode'] == 'FAIL':
		print("!!! Authentication Failed !!!")
	login()

if __name__ == '__main__':
	login()