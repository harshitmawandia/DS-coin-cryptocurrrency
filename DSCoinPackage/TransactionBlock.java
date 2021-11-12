package DSCoinPackage;

import HelperClasses.*;

public class TransactionBlock {

    public Transaction[] trarray;
    public TransactionBlock previous;
    public MerkleTree Tree;
    public String trsummary;
    public String nonce;
    public String dgst;

    TransactionBlock(Transaction[] t) {
        trarray = t.clone();
        previous=null;
        Tree = new MerkleTree();
        trsummary = Tree.Build(trarray);
        dgst = null;
    }

    public boolean checkTransaction (Transaction t) {
        if(t.coinsrc_block==null){
            return true;
        }
        TransactionBlock currentBlock = this.previous;
        while(currentBlock!=t.coinsrc_block){
            for(Transaction i : currentBlock.trarray){
                if(t.coinID.equals(i.coinID)){
                    return false;
                }
            }
            currentBlock=currentBlock.previous;
        }
        for(Transaction i: t.coinsrc_block.trarray){
            if(i.coinID.equals(t.coinID) && i!=t && i.Destination==t.Source){
                return true;
            }
        }
        return false;
    }
}
