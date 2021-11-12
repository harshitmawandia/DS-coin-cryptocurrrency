package DSCoinPackage;
import HelperClasses.*;

import java.util.ArrayList;

public class Moderator
{


    public void initializeDSCoin(DSCoin_Honest DSObj, int coinCount) throws EmptyQueueException {
        Members members = new Members();
        members.UID = "Moderator";
        if(DSObj.latestCoinID==null){
            int count = 100000;
            int j = 0;
            for(int i = 0; i< coinCount; i++){

                    Transaction transaction = new Transaction();
                    transaction.Source = members;
                    transaction.Destination = DSObj.memberlist[j];
                    transaction.coinID = Integer.toString(count);
                    transaction.coinsrc_block = null;
                    DSObj.latestCoinID = Integer.toString(count);
                    count++;
                    DSObj.pendingTransactions.AddTransactions(transaction);

                if (j<DSObj.memberlist.length-1){
                    j++;
                }else{
                    j=0;
                }
            }

            for(int  i = 0; i<coinCount/DSObj.bChain.tr_count;i++){
                Transaction[] transactions = new Transaction[DSObj.bChain.tr_count];
                for( j = 0; j < DSObj.bChain.tr_count;j++){
                    transactions[j] = DSObj.pendingTransactions.RemoveTransaction();
                }
                TransactionBlock transactionBlock = new TransactionBlock(transactions);
                for (Transaction transaction : transactions) {
                    if (transaction.Destination.mycoins == null) {
                        transaction.Destination.mycoins = new ArrayList<>();
                    }
                    transaction.Destination.mycoins.add(new Pair<>(transaction.coinID, transactionBlock));
                }
                DSObj.bChain.InsertBlock_Honest(transactionBlock);
            }

        }
    }

    public void initializeDSCoin(DSCoin_Malicious DSObj, int coinCount) throws EmptyQueueException {
        Members members = new Members();
        members.UID = "Moderator";
        if(DSObj.latestCoinID==null){
            int count = 100000;
            int j=0;
            for(int i = 0; i< coinCount; i++){

                Transaction transaction = new Transaction();
                transaction.Source = members;
                transaction.Destination = DSObj.memberlist[j];
                transaction.coinID = Integer.toString(count);
                transaction.coinsrc_block = null;
                DSObj.latestCoinID = Integer.toString(count);
                count++;
                DSObj.pendingTransactions.AddTransactions(transaction);
                if (j<DSObj.memberlist.length-1){
                    j++;
                }else{
                    j=0;
                }
            }

            for(int  i = 0; i<coinCount/DSObj.bChain.tr_count;i++){
                Transaction[] transactions = new Transaction[DSObj.bChain.tr_count];
                for( j = 0; j < DSObj.bChain.tr_count;j++){
                    transactions[j] = DSObj.pendingTransactions.RemoveTransaction();
                }
                TransactionBlock transactionBlock = new TransactionBlock(transactions);
                for (Transaction transaction : transactions) {
                    if (transaction.Destination.mycoins == null) {
                        transaction.Destination.mycoins = new ArrayList<>();
                    }
                    transaction.Destination.mycoins.add(new Pair<>(transaction.coinID, transactionBlock));
                }
                DSObj.bChain.InsertBlock_Malicious(transactionBlock);
            }

        }
    }
}
