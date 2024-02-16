#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  CryptoPP::SecByteBlock shared_key = crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value); // this is s in the diagram on page 4
  this->AES_key = crypto_driver->AES_generate_key(shared_key);
  this->HMAC_key = crypto_driver->HMAC_generate_key(shared_key);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change (i.e. the direction of communication 
 * changes, like Bob now sends a message to Alice); if so, update them.

 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  
  // It is my first time sending, so I need to initialize new DH Ratchet keys
  if (DH_switched) {
    auto [dh, privateKey, publicKey] = crypto_driver->DH_initialize(DH_params);
    prepare_keys(dh, privateKey, this->DH_last_other_public_value); 
    this->DH_current_public_value = publicKey;
    this->DH_current_private_value = privateKey;
    this->DH_switched = false;
  } 
  
  // I have been sending messages, so we don't generate new keys
  auto [ciphertext, iv] = crypto_driver->AES_encrypt(this->AES_key, plaintext);
  std::string mac = crypto_driver->HMAC_generate(this->HMAC_key, concat_msg_fields(iv, this->DH_current_public_value, ciphertext));

  // Return new message struct
  Message_Message msg;
  msg.iv = iv;
  msg.public_value = this->DH_current_public_value;
  msg.ciphertext = ciphertext;
  msg.mac = mac;
  return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message msg) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  // DH_current_public_value is Bob's current public value
  // DH_last_other_public_value is Alice's last sent public value

  if (msg.public_value != this->DH_last_other_public_value) {
    DH dh(this->DH_params.p, this->DH_params.q, this->DH_params.g);
    // auto [dh, privateValue, publicValue] = crypto_driver->DH_initialize(this->DH_params);
    this->DH_last_other_public_value = msg.public_value;
    this->prepare_keys(dh, this->DH_current_private_value, this->DH_last_other_public_value); 
    this->DH_switched = true;
  }
  // Verify MAC
  bool valid = crypto_driver->HMAC_verify(this->HMAC_key, concat_msg_fields(msg.iv, msg.public_value, msg.ciphertext), msg.mac);
  // Decrypt message
  std::string decrypted_message = crypto_driver->AES_decrypt(this->AES_key, msg.iv, msg.ciphertext);
  return std::make_pair(decrypted_message, valid);
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`.
 * `command` can be either "listen" or "connect"; the listener should `read()`
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value. 
 * 4) Listen for the other party's public value.
 * 5) Generate DH, AES, and HMAC keys and set local variables

 use public value message somewhere in here
 */
void Client::HandleKeyExchange(std::string command) {
  this->DH_switched = true;
  if (command == "listen") {
    std::vector<unsigned char> params = this->network_driver->read();
    this->DH_params.deserialize(params);
  }
  else if (command == "connect") {
    this->DH_params = this->crypto_driver->DH_generate_params();
    std::vector<unsigned char> data;
    this->DH_params.serialize(data);
    this->network_driver->send(data);
  }
  else {
    throw std::runtime_error("bad command");
  }
  auto [dh, privateValue, publicValue] = this->crypto_driver->DH_initialize(this->DH_params);
  this->DH_current_private_value = privateValue;
  this->DH_current_public_value = publicValue;

  PublicValue_Message msg;
  msg.public_value = this->DH_current_public_value;
  std::vector<unsigned char> send_data;
  msg.serialize(send_data);
  this->network_driver->send(send_data);

  PublicValue_Message msg_2;
  std::vector<unsigned char> public_val = this->network_driver->read();
  msg_2.deserialize(public_val);
  this->DH_last_other_public_value = msg_2.public_value;

  this->prepare_keys(dh, this->DH_current_private_value, this->DH_last_other_public_value);
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}