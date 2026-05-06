/* 
 * Provides 
 *  - A class that describes an applicative message intended to be transported as a DoDWAN message.
 *    Such a message can be sent or received, and contains either a short text or a file
 *
 *  - A service that allows athe user to subscribes to applicative messages, publish, receive them, 
 *    and store the received messages in a persistent storage
 */

console.log("Start module message.js");

import * as napicli from "@casa/napi-ws-client"

//import * as util from "./util.js"
//import * as pubsub from "./pubsub.js"

import * as persist from "./persistence.js"

/*
 * Class Message ---------------------------------------------
 *   inout {String} either "in" or "out"
 *   date {String} "MM/DD hh:mm:ss.sss"
 *   mid {String} 
 *   ptype {String} either "file" or "text" 
 *   desc  {Descriptor}
 *   payload {String} b64-encoded string (of utf8 for ptype text, and of byte array for ptype file) 
 */
export class Message {
    constructor() {
        this.inout = null;
        this.date = null;
        this.mid = null;
        this.ptype = null;
        this.desc = null;
        this.payload = null;
    }

    setDateFromCurrentTime() {
        let d = new Date(Date.now());
        this.date = pad(d.getMonth()+1) + "/" + pad(d.getDate()) + " " +
                pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
    }

    toJson() {
        return JSON.stringify(this);
    }

    static fromJson(str) {
        return Object.assign(new Message(), JSON.parse(str));
    }

}

function pad(n) {
    return (n < 10 ? "0" : "") + n;
}





/*
 * Class MessageService ---------------------------------------------
 */
class MessageService {

    constructor() {

        // List of published messages (key=msg id, value=Message)
        this.pubList = new Map();

        // List of set subscriptions (key=subscription key, value=Descriptor)
        this.subsList = new Map();

        // List of received messages (key=msg id, value=Message)
        this.recepList = new Map();

        // Global error
        this.onError = function () {
            console.log("Empty onError()");
        };
        // Notification of a the recpetion of a message
        this.onReceived = function () {
            console.log("Empty onReceived()");
        };

    }

    /*
     * Setters for callbacks
     */
    setOnError(f) {
        this.onError = f;
    }
    setOnReceived(f) {
        this.onReceived = f;
    }
   




    /*
     * Publishes a message
     * @param {Message} msg the message to be published
     * @param {function(Message)} after - the callback passing the message, to execute after completion
     */
    publish(msg, after) {   
        
        napicli.pubsub.service.publishBuffer(msg.desc, msg.payload,
          
            () => {    
                msg.setDateFromCurrentTime();
                this.pubList.set(msg.mid, msg);
                persist.addPubListStorage(msg);
                after(msg);
            },
            
            (error) => { alert("Publication error: "+error); }
        );
    }


    /*
     * Makes a subscription
     * @param {Descriptor} pattern - the descriptor that contains the subscription pattern
     * @param {function(Message) afterReception - callback passing the received message after the processor work
     * @param {function(string)} afterSubscribe - callback passing the subscription key after completion of the subscription
     */
    subscribe(pattern, afterReception, afterSubscribe) {
        let newSubsKey = "s" + napicli.util.uniqueId();
        console.log("Subscribe "+ newSubsKey + " : " + JSON.stringify(pattern));

        napicli.pubsub.service.addSubscription(newSubsKey, pattern, 
            //processor
            (rdesc) => { 
               this.messageProcessor(rdesc, afterReception); 
            },
           
            // ok 
            () => {
               this.subsList.set(newSubsKey, pattern);
               persist.addSubsListStorage(newSubsKey, pattern);
               afterSubscribe(newSubsKey);
            },
                       
            //error
            (error) => { alert("Subscription error: "+error); }
         
        );
    }
    
    
    
    /*
     * Processes the arrival of a message (recv_desc): obtain the payload to build a message
     * @private
     * @param {mid} the received message id 
     * @param {desc} the received descriptor 
     * @param {function(string)} after - callback passing the message after processor completion
     */
     messageProcessor(desc, after) {
        console.log("Message processor called with desc="+JSON.stringify(desc));
        let mid = desc._docid;
        
        if (this.recepList.has(mid)) return;

        // Register the message (without its payload)
        let msg = new Message();
        msg.mid = mid;
        msg.inout = "in";
        msg.desc = desc;
        //msg.desc = Object.assign(new napicli.pubsub.Descriptor(), desc);
        msg.ptype = desc._webopp_ptype;

       
        // Get the payload 
        napicli.pubsub.service.getAsBuffer(mid,
            (payload) => {
               msg.payload = payload;
               msg.setDateFromCurrentTime();
               this.recepList.set(mid, msg);
               persist.addRecepListStorage(msg);
               after(msg);
            },
            () => {
               console.log("Processor error");
            }
        );

        
    }
    
    

    /*
     * Removes a subscription
     * @param {function()} [after] - callback after completion
     */
    unsubscribe(skey, after) {
        console.log("Unsubscribe : " + skey);

        napicli.pubsub.service.removeSubscription(skey,
            //ok
            () => { 
                this.subsList.delete(skey);
                persist.removeSubsListStorage(skey);
                if (after !== undefined) after();
            },
              
            //error
            (error) => { alert("Unsubscription error: "+error); }
        );      
    }



    /*
     *  Restores the publish, subscribe, and reception lists from the persistance storage
     *  For each element restored, a treatment is applied. 
     *  Previous contents of the lists are cleared.
     * @param {function(msg)} pubFunc the treatment applied to a restored published message
     * @param {function(skey, desc)} subsFunc the treatment applied to a restored subscription (subsciption key, descriptor)
     * @param {function(msg)} recepFunc the treatment applied to a restored received message
     */
    restorePersistedLists(pubFunc, subsFunc, recepFunc) {
        persist.loadListsStorage(this.pubList, this.subsList, this.recepList);
        for (let [msgId, msg] of this.pubList) {
            pubFunc(msg);
        }
        for (let [skey, desc] of this.subsList) {
            subsFunc(skey, desc);
        }
        for (let [msgId, msg] of this.recepList) {
            recepFunc(msg);
        }
    }

    /*
     * Clears the list of published messages.
     * Both the in-memory list and the list in persistant storage are cleared.
     */
    clearPersistedPubList() {
        this.pubList.clear();
        persist.removeAllPubListStorage();
    }

    /*
     * Clears the list of subscriptions.
     * Unsubscribes also all the registered subscriptions.
     * Both the in-memory list and the list in persistant storage are cleared.
     */
    clearPersistedSubsList() {
        for (let [k, v] of this.subsList) {
            service.unsubscribe(k);
        }
        persist.removeAllSubsListStorage();
    }

    /*
     * Clears the list of received messages.
     * Both the in-memory list and the list in persistant storage are cleared.
     */
    clearPersistedRecepList() {
        this.servicerecepList.clear();
        persist.removeAllRecepListStorage();
    }



  

    /* Tells DoDWAN to send the messages that are in the cache and that match our subscriptions   
     * but that we have not received (because the session was not active) 
     * @param {function(Message)} afterEach - callback passing the message triggred after the reception of each message 
     */
    askForMissedMessages(afterEach) {
        
        napicli.pubsub.service.getMatching(Array.from(this.subsList.keys()),
            //ok
             (mids) => {
                for (let mid of mids) {
                    if (! this.recepList.has(mid)) {
                         // Issue a get_desc command
                         napicli.pubsub.service.get_desc(mid, 
                             (desc) => {
                                 messageProcessor(desc, afterEach);
                             },
                             
                             (error) => { console.log("Missed message "+mid + " could not be retrieved: "+error); }
                             );
                    }  
                }       
            }
        );
     
    }
    
    
    
}





// Singleton
export var service = new MessageService();

