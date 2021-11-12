package DSCoinPackage;

import java.util.*;
import HelperClasses.*;

public class Members
{

    public String UID;
    public List<Pair<String, TransactionBlock>> mycoins;
    public Transaction[] in_process_trans;

    public void initiateCoinsend(String destUID, DSCoin_Honest DSobj) {
        Transaction transaction = new Transaction();
        transaction.coinID = mycoins.get(0).first;
        transaction.coinsrc_block = mycoins.get(0).second;
        mycoins.remove(0);
        transaction.Source = this;
        for(Members members : DSobj.memberlist){
            if(members.UID.equals(destUID)){
                transaction.Destination=members;
            }
        }
        Transaction[] temp = new Transaction[in_process_trans==null?1:in_process_trans.length+1];
        for(int i = 0; i < (in_process_trans==null?0:in_process_trans.length);i++){
            temp[i] = in_process_trans[i];
        }
        temp[in_process_trans==null?0:in_process_trans.length]=transaction;
        in_process_trans = temp;
        TransactionQueue queue = DSobj.pendingTransactions;
        queue.AddTransactions(transaction);
    }

    public void initiateCoinsend(String destUID, DSCoin_Malicious DSobj) {
        Transaction transaction = new Transaction();
        transaction.coinID = mycoins.get(0).first;
        transaction.coinsrc_block = mycoins.get(0).second;
        mycoins.remove(0);
        transaction.Source = this;
        for(Members members : DSobj.memberlist){
            if(members.UID.equals(destUID)){
                transaction.Destination=members;
            }
        }
        Transaction[] temp = new Transaction[in_process_trans==null?1:in_process_trans.length+1];
        for(int i = 0; i < (in_process_trans==null?0:in_process_trans.length);i++){
            temp[i] = in_process_trans[i];
        }
        temp[in_process_trans==null?0:in_process_trans.length]=transaction;
        in_process_trans = temp;
        TransactionQueue queue = DSobj.pendingTransactions;
        queue.AddTransactions(transaction);
    }

    public List<Pair<String, String>> SiblingCoupledPath (int doc_idx,int numdocs,TreeNode rootnode){
        ArrayList<Integer> path = new ArrayList<>();
        int a = doc_idx;
        for(int i = 0; i < Math.log(numdocs)/Math.log(2)+1;i++){
            path.add(a);
            a=(a)/2;
        }
        ArrayList<Pair<String,String>> SCpath = new ArrayList<>();
        TreeNode currentNode = rootnode;
        for(int i= path.size()-1; i >=0; i--){
            Pair<String,String> pair;
            if(path.get(i)%2==0){
                String s1 = currentNode.val;
                String s2;
                if(currentNode.parent!=null){
                    s2 = currentNode.parent.right.val;
                }else{
                    s2 = null;
                }
                pair = new Pair<>(s1,s2);
            }else{
                String s2 = currentNode.val;
                String s1;
                if(currentNode.parent!=null){
                    s1 = currentNode.parent.left.val;
                }else{
                    s1 = null;
                }
                pair = new Pair<>(s1,s2);
            }
            if(i>0){
                if(path.get(i-1)%2==0){
                    currentNode=currentNode.left;
                }else{
                    currentNode=currentNode.right;
                }
            }
            SCpath.add(pair);

        }

        return reverseArrayList(SCpath);
    }

    public ArrayList<Pair<String,String>> reverseArrayList(ArrayList<Pair<String,String>> alist){
        ArrayList<Pair<String,String>> revArrayList = new ArrayList<>();
        for (int i = alist.size() - 1; i >= 0; i--) {
            revArrayList.add(alist.get(i));
        }
        return revArrayList;
    }

    public List<Pair<String, String>> dgstList(ArrayList<TransactionBlock> blockArrayList){
        Pair<String,String> first = new Pair<>(blockArrayList.get(blockArrayList.size()-1).previous!=null?blockArrayList.get(blockArrayList.size()-1).previous.dgst:"DSCoin", null);
        ArrayList<Pair<String,String>> arrayList = new ArrayList<>();
        arrayList.add(first);
        for(int i = blockArrayList.size()-1;i>=0;i--){
            String s1 = blockArrayList.get(i).dgst;
            String s2 = arrayList.get(arrayList.size()-1).first+"#"+blockArrayList.get(i).trsummary+"#"+blockArrayList.get(i).nonce;
            Pair<String,String> pair = new Pair<>(s1,s2);
            arrayList.add(pair);
        }
        return arrayList;
    }

    public Pair<List<Pair<String, String>>, List<Pair<String, String>>> finalizeCoinsend (Transaction tobj, DSCoin_Honest DSObj) throws MissingTransactionException {

        TransactionBlock currentBlock = DSObj.bChain.lastBlock;
        ArrayList<TransactionBlock> arrayList = new ArrayList<>();
        while(currentBlock!=null){
            arrayList.add(currentBlock);
            for(int i = 0; i< currentBlock.trarray.length;i++){
                if(tobj==currentBlock.trarray[i]){

                    List<Pair<String, String>> siblingPath = SiblingCoupledPath(i,currentBlock.trarray.length,currentBlock.Tree.rootnode);
                    List<Pair<String,String>> dgstList = dgstList(arrayList);
                    Pair<List<Pair<String, String>>, List<Pair<String, String>>> pair = new Pair<>(siblingPath,dgstList);

                    ArrayList<Transaction> arrayList1 = new ArrayList<>( Arrays.asList(in_process_trans));
                    arrayList1.remove(tobj);

                    in_process_trans = new Transaction[arrayList1.size()];
                    for(int j = 0; j<arrayList1.size();j++){
                        in_process_trans[j] = arrayList1.get(j);
                    }
                    Pair<String,TransactionBlock> transactionBlockPair = new Pair<>(tobj.coinID,currentBlock);
                    tobj.Destination.mycoins.add(transactionBlockPair);
                    MergeSort mergeSort = new MergeSort((ArrayList<Pair<String, TransactionBlock>>) tobj.Destination.mycoins);
                    tobj.Destination.mycoins = mergeSort.sort();

                    return pair;

                }
            }
            currentBlock=currentBlock.previous;
        }
        throw new MissingTransactionException();

    }

    public void MineCoin(DSCoin_Honest DSObj) throws EmptyQueueException {
        Transaction[] transactions = new Transaction[DSObj.bChain.tr_count];
        int i = 0;
        TransactionQueue queue = DSObj.pendingTransactions;
        assert  queue.numTransactions>=DSObj.bChain.tr_count - 1;
        while(transactions[DSObj.bChain.tr_count - 2]==null){
            Transaction tr = queue.RemoveTransaction();
            boolean b = true;
            for(int j = 0; j<i;j++){
                if (transactions[j].coinID.equals(tr.coinID)) {
                    b = false;
                    break;
                }
            }
            if(b){
                transactions[i]=tr;
                i++;
            }
        }
        int latestCoinID = Integer.parseInt(DSObj.latestCoinID);
        latestCoinID++;
        DSObj.latestCoinID = Integer.toString(latestCoinID);

        Transaction minerRewardTransaction = new Transaction();
        minerRewardTransaction.coinID = DSObj.latestCoinID;
        minerRewardTransaction.Source = null;
        minerRewardTransaction.Destination = this;
        minerRewardTransaction.coinsrc_block = null;

        transactions[DSObj.bChain.tr_count-1] = minerRewardTransaction;

        TransactionBlock tB = new TransactionBlock(transactions);

        DSObj.bChain.InsertBlock_Honest(tB);

        mycoins.add(new Pair<>(DSObj.latestCoinID,tB));


    }

    public void MineCoin(DSCoin_Malicious DSObj) throws EmptyQueueException {
        Transaction[] transactions = new Transaction[DSObj.bChain.tr_count];
        int i = 0;
        TransactionQueue queue = DSObj.pendingTransactions;
        assert  queue.numTransactions>=DSObj.bChain.tr_count - 1;
        while(transactions[DSObj.bChain.tr_count - 2]==null){
            Transaction tr = queue.RemoveTransaction();
            boolean b = true;
            for(int j = 0; j<i;j++){
                if (transactions[j].coinID.equals(tr.coinID)) {
                    b = false;
                    break;
                }
            }
            if(b){
                transactions[i]=tr;
                i++;
            }
        }
        int latestCoinID = Integer.parseInt(DSObj.latestCoinID);
        latestCoinID++;
        DSObj.latestCoinID = Integer.toString(latestCoinID);

        Transaction minerRewardTransaction = new Transaction();
        minerRewardTransaction.coinID = DSObj.latestCoinID;
        minerRewardTransaction.Source = null;
        minerRewardTransaction.Destination = this;
        minerRewardTransaction.coinsrc_block = null;

        transactions[DSObj.bChain.tr_count-1] = minerRewardTransaction;

        TransactionBlock tB = new TransactionBlock(transactions);

        DSObj.bChain.InsertBlock_Malicious(tB);

        mycoins.add(new Pair<>(DSObj.latestCoinID,tB));
    }

    public static class MergeSort {
        private ArrayList<Pair<String, TransactionBlock>> inputArray;

        public ArrayList<Pair<String, TransactionBlock>> sort() {
            divide(0, this.inputArray.size()-1);
            return inputArray;
        }

        public MergeSort(ArrayList<Pair<String, TransactionBlock>> inputArray){
            this.inputArray = (ArrayList<Pair<String, TransactionBlock>>) inputArray.clone();
        }


        public void divide(int startIndex,int endIndex){

            if(startIndex<endIndex && (endIndex-startIndex)>=1){
                int mid = (endIndex + startIndex)/2;
                divide(startIndex, mid);
                divide(mid+1, endIndex);

                merger(startIndex,mid,endIndex);
            }
        }

        public void merger(int startIndex,int midIndex,int endIndex){

            ArrayList<Pair<String, TransactionBlock>> mergedSortedArray = new ArrayList<Pair<String, TransactionBlock>>();

            int leftIndex = startIndex;
            int rightIndex = midIndex+1;

            while(leftIndex<=midIndex && rightIndex<=endIndex){
                if(inputArray.get(leftIndex).first.compareTo(inputArray.get(rightIndex).first)<0){
                    mergedSortedArray.add(inputArray.get(leftIndex));
                    leftIndex++;
                }else{
                    mergedSortedArray.add(inputArray.get(rightIndex));
                    rightIndex++;
                }
            }

            while(leftIndex<=midIndex){
                mergedSortedArray.add(inputArray.get(leftIndex));
                leftIndex++;
            }

            while(rightIndex<=endIndex){
                mergedSortedArray.add(inputArray.get(rightIndex));
                rightIndex++;
            }

            int i = 0;
            int j = startIndex;
            while(i<mergedSortedArray.size()){
                inputArray.set(j, mergedSortedArray.get(i++));
                j++;
            }
        }
    }
}
