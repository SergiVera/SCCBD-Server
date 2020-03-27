'use strict';

const rsa = require('rsa');
const bc = require('bigint-conversion');

let keyPair;

/**
 * Get the public Key function
 * @param {*} req Request
 * @param {*} res Response
 */
async function getPublicKey(req, res) {
  try {
    keyPair = await rsa.generateRandomKeys();
    res.status(200).send({
      e: bc.bigintToHex(keyPair["publicKey"]["e"]),
      n: bc.bigintToHex(keyPair["publicKey"]["n"])
    })
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

/**
 * Encrypt a message
 * @param {*} req Request
 * @param {*} res Response
 */
async function postMsg(req, res) {
  try {
    const c = req.body.msg;
    const m = await keyPair["privateKey"].decrypt(bc.hexToBigint(c));
    res.status(200).send({msg: bc.bigintToHex(m)})
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

/**
 * Sign a message
 * @param {*} req Request
 * @param {*} res Response
 */
async function signMsg(req, res) {
  try {
    const m = bc.hexToBigint(req.body.msg);
    const s = await keyPair["privateKey"].sign(m);
    res.status(200).send({msg: bc.bigintToHex(s)})
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

/**
 * Get the home message
 * @param {*} req Request
 * @param {*} res Response
 */
async function getMsg(req, res) {
  try {
    res.status(200).send({msg: "Hello"})
  } catch (err) {
    res.status(500).send({msg: "Something bad happened"})
  }
}

module.exports = {
  postMsg,
  signMsg,
  getMsg,
  getPublicKey
};
