import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class TxHandler {

    UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        ArrayList<UTXO> allUTXO = utxoPool.getAllUTXO();
        HashSet<UTXO> dejavu = new HashSet<>();

        double total = 0;
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInputs().get(i);

            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            // (1)
            if (!allUTXO.contains(utxo)) return false;
            // (3)
            if (dejavu.contains(utxo)) return false;
            dejavu.add(utxo);

            Transaction.Output prevOutput = utxoPool.getTxOutput(utxo);

            // (2) signatures
            byte[] msg = tx.getRawDataToSign(i);
            if (!Crypto.verifySignature(prevOutput.address, msg, input.signature)) return false;

            total += prevOutput.value;
        }
        for (Transaction.Output output : tx.getOutputs()) {
            // (4)
            if (output.value < 0) return false;
            total -= output.value;
        }
        // (5)
        return total >= 0;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> result = new ArrayList<>();
        for (Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {
                result.add(tx);
                processTransaction(tx);
            }
        }
        return result.toArray(new Transaction[0]);
    }

    private void processTransaction(Transaction tx) {
        for (Transaction.Input input : tx.getInputs()) {
            utxoPool.removeUTXO(new UTXO(input.prevTxHash, input.outputIndex));
        }
        byte[] txHash = tx.getHash();
        for (int i = 0; i < tx.numOutputs(); i++) {
            utxoPool.addUTXO(new UTXO(txHash, i), tx.getOutput(i));
        }
    }

}
