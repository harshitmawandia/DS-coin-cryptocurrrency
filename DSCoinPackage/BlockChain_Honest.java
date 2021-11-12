package DSCoinPackage;

import HelperClasses.*;

public class BlockChain_Honest {

    public int tr_count;
    public static final String start_string = "DSCoin";
    public TransactionBlock lastBlock;

    public String calcNonce(String prev_dgst, String trsummary){
        long counter = 1000000001L;
        CRF crf = new CRF(64);
        while (true){
            String s = crf.Fn(prev_dgst+"#"+trsummary+"#"+counter);
            if(s.substring(0,4).matches("0000")){
                return Long.toString(counter);
            }
            counter++;
        }
    }

    public void InsertBlock_Honest (TransactionBlock newBlock) {
        CRF crf = new CRF(64);

        newBlock.previous = lastBlock;

        if(newBlock.previous==null){
            newBlock.nonce = calcNonce(start_string, newBlock.trsummary);
            newBlock.dgst = crf.Fn(start_string+"#"+newBlock.trsummary+"#"+newBlock.nonce);
        }else{
            newBlock.nonce = calcNonce(newBlock.previous.dgst, newBlock.trsummary);
            newBlock.dgst = crf.Fn(newBlock.previous.dgst+"#"+newBlock.trsummary+"#"+newBlock.nonce);
        }

        lastBlock = newBlock;
    }
}
