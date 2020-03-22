import { BitGo } from '../../bitgo';
import { BaseCoin } from '../baseCoin';
import { AbstractUtxoCoin, AddressInfo, UnspentInfo, UtxoNetwork } from './abstractUtxoCoin';
import * as common from '../../common';
import { toOutputScript, Transaction, TransactionBuilder } from 'bitcoinjs-lib';
import * as bitcoin from 'bitgo-utxo-lib';
import * as request from 'superagent';
import * as _ from 'lodash';
import * as Bluebird from 'bluebird';
const co = Bluebird.coroutine;

export interface TransactionInfo {
  transactionHex: string,
}

export class Btc extends AbstractUtxoCoin {
  constructor(bitgo: BitGo, network?: UtxoNetwork) {
    super(bitgo, network || bitcoin.networks.bitcoin);
  }

  static createInstance(bitgo: BitGo): BaseCoin {
    return new Btc(bitgo);
  }

  getChain(): string {
    return 'btc';
  }

  getFamily(): string {
    return 'btc';
  }

  getFullName(): string {
    return 'Bitcoin';
  }

  supportsBlockTarget(): boolean {
    return true;
  }

  supportsP2shP2wsh(): boolean {
    return true;
  }

  supportsP2wsh(): boolean {
    return true;
  }

  getRecoveryFeePerBytes(): Bluebird<number> {
    const self = this;
    return co<number>(function *getRecoveryFeePerBytes() {
      const recoveryFeeUrl = yield self.getRecoveryFeeRecommendationApiBaseUrl();

      const publicFeeDataReq = request.get(recoveryFeeUrl);
      publicFeeDataReq.forceV1Auth = true;
      const publicFeeData = yield publicFeeDataReq.result();

      if (_.isInteger(publicFeeData.hourFee)) {
        return publicFeeData.hourFee;
      } else {
        return 100;
      }
    }).call(this);
  }

  getRecoveryFeeRecommendationApiBaseUrl(): Bluebird<string> {
    return Bluebird.resolve('https://bitcoinfees.earn.com/api/v1/fees/recommended');
  }

  recoveryBlockchainExplorerUrl(url: string): string {
    return common.Environments[this.bitgo.getEnv()].smartBitApiBaseUrl + '/blockchain' + url;
  }

  getAddressInfoFromExplorer(addressBase58: string): Bluebird<any> {
    const self = this;
    return co(function *getAddressInfoFromExplorer() {
      const addrInfo = yield request.get(self.recoveryBlockchainExplorerUrl(`/address/${addressBase58}`)).result();

      addrInfo.txCount = addrInfo.address.total.transaction_count;
      addrInfo.totalBalance = addrInfo.address.total.balance_int;

      return addrInfo;
    }).call(this);
  }

  getTransactionHexFromExplorer(txid: string): string {
    const self = this;
    return co(function *getAddressInfoFromExplorer() {
      const txInfo = yield request.get(self.recoveryBlockchainExplorerUrl(`/tx/${txid}/hex`)).result();
      return txInfo.hex[0].hex;
    }).call(this);
  }

  // For BTC the unspent info can e.g. be found here https://api.smartbit.com.au/v1/blockchain/address/3EDynTAW8JFk4Tn8EahnbGzrw1QZUFBCtF/unspent
  getUnspentInfoFromExplorer(addressBase58: string): Bluebird<UnspentInfo[]> {
    const self = this;
    return co(function *getUnspentInfoFromExplorer() {
      const unspentInfo = yield request.get(self.recoveryBlockchainExplorerUrl(`/address/${addressBase58}/unspent`)).result();

      const unspents = unspentInfo.unspent;

      unspents.forEach(function processUnspent(unspent) {
        unspent.amount = unspent.value_int;
      });

      return unspents;
    }).call(this);
  }

  public verifyRecoveryTransaction(txInfo: TransactionInfo): Bluebird<any> {
    const self = this;
    return co(function *verifyRecoveryTransaction() {
      const decodedTx = yield request.post(self.recoveryBlockchainExplorerUrl(`/decodetx`))
      .send({ hex: txInfo.transactionHex })
      .result();

      const transactionDetails = decodedTx.transaction;

      const tx = bitcoin.Transaction.fromHex(txInfo.transactionHex, this.network);
      if (transactionDetails.TxId !== tx.getId()) {
        console.log(transactionDetails.TxId);
        console.log(tx.getId());
        throw new Error('inconsistent recovery transaction id');
      }

      return transactionDetails;
    }).call(this);
  }

  public sendOmniToken(fromAddress: string, toAddress: string, tokenAmount: number, tokenId: number, fundingTxid?: string): Bluebird<any> {
    const self = this;
    return co(function* () {
        if (!self.isValidAddress(fromAddress)){
          throw new Error(`Invalid fromAddress. Got: ${fromAddress}`);
        }
        if (!self.isValidAddress(toAddress)){
          throw new Error(`Invalid toAddress. Got: ${toAddress}`);
        }

      let txBuilder: TransactionBuilder = new TransactionBuilder();

      // Add all inputs to the transaction
      let inputValueInSatoshi: number = 0;
      if (fundingTxid) {
        const recipientAddressAsOutputScript: string = toOutputScript(toAddress);

        // Get raw hex from txid and decode the transaction
        const txHex: string = yield self.getTransactionHexFromExplorer(fundingTxid);
        const fundingTx = Transaction.fromHex(txHex);

        // Loop over outputs in fundingTxid and select those that are going to `fromAddress` (usually just one output)
        let vout: number;
        for (vout = 0; vout < fundingTx.outs.length; vout++) {
          if (fundingTx.outs[vout].script.toString('hex') !== recipientAddressAsOutputScript){
            continue;
          }

          txBuilder.addInput(fundingTxid, vout, 0xffffffff, fundingTx.outs[vout].script);
          inputValueInSatoshi += fundingTx.outs[vout].value.readUIntBE();
        }
      } else {
        // Get funding UTXOs. These are the inputs of the of the TX. We choose to consume all UTXOs for `fromAddress`.
        const utxos: UnspentInfo[] = yield self.getUnspentInfoFromExplorer(fromAddress);
        utxos.forEach(utxo => {
          txBuilder.addInput(utxo.txid, utxo.n, 0xffffffff, Buffer.from(utxo.script_pub_key.hex, 'hex'));
          inputValueInSatoshi += utxo.value_int;
        });
      }

      // Sanity check. Number.MAX_SAFE_INTEGER = 9007199254740991 ~= 90 mio BTC so this should never happen
      if (inputValueInSatoshi > Number.MAX_SAFE_INTEGER){
        throw new Error("Invalid input satoshi amount for omni recovery transaction. Got: " + inputValueInSatoshi.toString());
      }

      // Add all outputs to the transaction
      // Add dust output to recipient
      txBuilder.addOutput(toAddress, self.getDustAmountInSatoshi());

      // Add the omni output. This is the output that follows the Omni protocol
      // This check sets a limit of max transfer to 90 mio. Omni units (90 mio. USD for Tether).
      // This limit could be remove by using a JS big number type instead of the native number
      const unitValue: number = tokenAmount * 1e8;
      if (unitValue > Number.MAX_SAFE_INTEGER){
        throw new Error("Cannot handle this big a OMNI token amount: " + tokenAmount.toString());
      }

      // This snippet was found on https://bitcoin.stackexchange.com/questions/74511/how-to-create-an-omnilayer-transaction-by-myself
      const simple_send = [
        "6f6d6e69", // omni
        "0000",     // version
        tokenId.toString(16).padStart(12, '0'), // Determines which Omni token is being transferred
        unitValue.toString(16).padStart(16, '0')
      ].join('')
      const data = Buffer.from(simple_send, "hex");
      const omniOutput = bitcoin.script.compile([
        bitcoin.opcodes.OP_RETURN,
        data
      ]);
      txBuilder.addOutput(omniOutput, 0)

      // Add change amount to `fromAddress`
      const feeInSatoshiPerBytes: number = yield self.getRecoveryFeePerBytes();

      // Add dummy-output to get better size when calculating fee. But the signatures are not added yet, so this underestimates the actual size
      txBuilder.addOutput(fromAddress, 0);
      const vSizeInVBytes: number = txBuilder.virtualSize();
      const shouldPayFeeInSatoshi: number = vSizeInVBytes * feeInSatoshiPerBytes;
      const changeAmountInSatoshi: number = inputValueInSatoshi - self.getDustAmountInSatoshi() - shouldPayFeeInSatoshi;
      txBuilder.outs[2].amount = changeAmountInSatoshi;
      if (changeAmountInSatoshi < self.getDustAmountInSatoshi()){
        throw new Error(`Insufficient BTC funds on ${fromAddress} to handle Omni recovery transaction`);
      }

      // Sanity check that we didn't mess up fee calculation
      const outputValue: number = txBuilder.outs.reduce((a, x) => a + x.value, 0);
      if (outputValue + feeInSatoshiPerBytes !== inputValueInSatoshi){
        throw new Error("Inconsistent fee amount discovered in transaction:" + JSON.stringify(txBuilder));
      }

      const unsignedTx: string =  txBuilder.build().toHex();

      return unsignedTx;
    }).call(this);
  }
}
