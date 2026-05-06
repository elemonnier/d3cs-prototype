/*
 * GUI for the Webopp application
 */

console.log("Start module dom.js");

import * as napicli from "@casa/napi-ws-client"

//import * as configuration from "./configuration.js"
//import * as pubsub from "./pubsub.js"

import * as message from "./message.js"

//import * as session from "./session.js"
//import * as peer from "./peer.js"
//import * as util from "./util.js"



const sessionStatus = {
    STOPPED:'stopped',
    STARTING:'starting',
    STARTED:'started'
};


window.onunload = quitApplication;

checkUniqueWindow();

restoreLists();


// Initialize main button handlers
document.getElementById("pub-collapse").onclick = clickPubCollapse;
document.getElementById("pub-button").onclick = clickPublish;
document.getElementById("pub-add-row").onclick = clickAddPubDescRow ;

document.getElementById("subs-collapse").onclick = clickSubsCollapse;
document.getElementById("subs-add-row").onclick = clickAddSubsDescRow;
document.getElementById("subs-button").onclick = clickSubscribe;

document.getElementById("recep-collapse").onclick = clickRecepCollapse;

document.getElementById("hamburger").onclick = clickHamburger;
document.getElementById("mi-clear-pub-list").onclick = clearPubList;
document.getElementById("mi-clear-subs-list").onclick = clearSubsList;
document.getElementById("mi-clear-recep-list").onclick = clearRecepList;
document.getElementById("mi-clear-all").onclick = clearAllAndQuit;

document.getElementById("connect-status").onclick = function() {window.location.reload();};
document.getElementById("connect-address").onkeydown = function (event) {if (event.keyCode === 13) clickConnect();};


// Clear Inputs
clearPubInputs();
clearSubsInputs();



// Listeners for peers and session events

napicli.peer.service.addListener(new napicli.peer.PeerListener(
    addPeer, removePeer, clearPeers
));

napicli.session.service.addListener(new napicli.session.SessionListener(
    onConnectionOpened, onConnectionClosed, onConnectionError,
    onSessionStarting, onSessionStarted, onSessionStopped
));







// Status handlers

function onSessionStarted() {
    setSessionStatus(sessionStatus.STARTED);

    napicli.peer.service.getPeers(addPeers);
    napicli.peer.service.getMyPeerName(setMyPeer);

    message.service.askForMissedMessages(addRecepListElt);

    activatePubsubButtons(true);
}


function onSessionStopped() {
    setSessionStatus(sessionStatus.STOPPED);
    activatePubsubButtons(false);
}

function onSessionStarting() {
    setSessionStatus(sessionStatus.STARTING);
    activatePubsubButtons(false);

}

function onConnectionError() {}
function onConnectionOpened() {}
function onConnectionClosed() {}




// Be ready to receive

let serverHost = window.localStorage.getItem("server_host");
let serverPort = window.localStorage.getItem("server_port");

if (serverHost === null) {
    serverHost = window.location.hostname;
    window.localStorage.setItem("server_host", serverHost);
}

if (serverPort === null) {
    serverPort = "8025";
    window.localStorage.setItem("server_port", serverPort);
}

napicli.configuration.service.config.server_host = serverHost;
napicli.configuration.service.config.server_port = serverPort;
document.getElementById("connect-address").value = serverHost+":"+serverPort;


napicli.session.service.start();




// Indicates that this window is the first that has launched the app
// (and has created the lock)
var IAmTheFirst;


/*
 * Checks if this is the sole application window
 * This is done with a lock item in the local storage.
 * As the lock may not have been released properly,
 * we ask the user to confirm that the lock should be overcome or not.
 */
function checkUniqueWindow() {
    //console.log("IAmTheFirst=" + IAmTheFirst);
    let lock = window.localStorage.getItem("appLock");
    //console.log("lock=" + lock);
    if (lock === "lock") {
        IAmTheFirst = false;
        let result = window.confirm("The Webopp application seems to be already running in another window or tab." +
                " Click OK if you want to continue anyway with this tab");
        if (!result) {
            //console.log("I give up. Clear the window.");
            document.body.innerHTML = "";

        } else {
            //console.log("I insist.");
        }

    } else {
        IAmTheFirst = true;
        addLock();
    }

}


function addLock() {
   console.log("add lock");
   window.localStorage.setItem("appLock", "lock");
}


function removeLock() {
    console.log("remove lock");
    window.localStorage.removeItem("appLock");
}


function quitApplication() {
    console.log("Quit application  [lock="+window.localStorage.getItem("AppLock")+"]");
    //console.log("Quitting Webopp [IAmTheFirst = "+IAmTheFirst+"]");
    if (IAmTheFirst) {
       removeLock();
    }
}

// =========================== Displaying peers ================================

function setMyPeer(peer) {
    console.log("setMyPeerId "+peer);
    var myIdContent = document.getElementById("my-id-content");
    myIdContent.innerHTML = peer;
}


function addPeers(peers) {
    for (let i in peers) {
        console.log("PubsSub adding initial peer " + peers[i]);
        addPeer(peers[i]);
    }
}

function addPeer(peer) {
  var peerContent = document.getElementById("peer-content");
  var newElt = document.createElement("SPAN");
  newElt.setAttribute("id","peerid_"+peer);
  newElt.setAttribute("class","peer");
  newElt.innerHTML = peer;
  peerContent.appendChild(newElt);

}


function removePeer(peer) {
   var elt = document.getElementById("peerid_"+peer);
   if (elt === null) {
       console.log("Peer "+peer+" cannot be removed");
       return;
   }
   elt.remove();
}

function clearPeers() {
   var peerContent = document.getElementById("peer-content");
   peerContent.innerHTML="";
}



// ================ Current descriptor for publishing and subscribing ==========

var pubDesc  = new  napicli.pubsub.Descriptor();
var subsDesc  = new napicli.pubsub.Descriptor();

 /*
 * Clears the current publish descriptor
 */
function clearPubDesc() {
    pubDesc = new napicli.pubsub.Descriptor();
}

/*
 * Clears the current subscription descriptor
 */
function clearSubsDesc() {
    subsDesc = new napicli.pubsub.Descriptor();
}






// ================ Restoration from Local Storage ======================
/*
 * Rebuild from the storage and display the lists of
 * published messages, set subscriptions and received messages
 */
function restoreLists() {
    message.service.restorePersistedLists(addPubListElt, addSubsListElt, addRecepListElt);
}


function clearPubList() {
    message.service.clearPersistedPubList;
    document.getElementById("pub-list").innerHTML="";
}

function clearSubsList() {
    message.service.clearPersistedSubsList();
    document.getElementById("subs-list").innerHTML="";
}

function clearRecepList() {
    message.service.clearPersistedRecepList();
    document.getElementById("recep-list").innerHTML="";
}

function clearAllAndQuit() {
    napicli.session.service.bye();
    window.localStorage.clear();
    window.onclick = function() {};
    document.body.innerHTML="Bye bye...";
}


// ========================= Status Bar ==================================

function setSessionStatus(status) {
    console.log("setSessionStatus : " + status);
    let elt = document.getElementById("connect-status");
    switch (status) {
       case sessionStatus.STARTED : elt.style.color = "limegreen"; break;
        case sessionStatus.STARTING : elt.style.color = "orange"; break;
         case sessionStatus.STOPPED : elt.style.color = "firebrick"; break;
    }
 }



// ================ Main  Button Clicks ==================================

function clickPublish() {

    // Invalidate the button
    activatePubButton(false);

    // Checks if the descriptor is unfinished
    if (document.getElementById("pub-input-key").value !== "") {
        addPubDescRow();
        //console.log("Publish descriptor completed with the input line");
    }

    // Build the out message
    let typedText = document.getElementById("pub-textpayload-input").value.trim();
    let files = document.getElementById("pub-file").files;
    let chosenFile = files.length === 0 ? null: files[0] ;

    // Checks if the message is empty (desc and payload empty)
    if ((Object.keys(pubDesc).length === 0)  &&
          (typedText === "") &&
          (chosenFile === null)
          ) {
        alert("Cannot publish an empty message");
        activatePubButton(true);
        return;
    }

    let msg = new message.Message();
    msg.inout = "out";
    msg.mid = napicli.util.uniqueId();
    msg.desc = pubDesc;
    // The text type is privileged, i.e., if both a chosen file and a typed text
    // are provided, the message will be a text message.
    // The message payload may be eventually empty (descriptor-only message)
    msg.ptype = (typedText !== "" || chosenFile === null) ? "text" : "file";


    // Complete the message wih its payload and publish it.
    if (msg.ptype === "text") {
        msg.desc._webopp_ptype = "text";
        //console.log("Publish data from text: size=" + typedText);
        msg.payload = napicli.util.stringToB64(typedText);
        message.service.publish(msg, afterPublish);
    }
    else {
        msg.desc._webopp_ptype = "file";
        msg.desc._webopp_pmime = chosenFile.type;
        msg.desc._webopp_file = chosenFile.name;

        let reader = new FileReader();

        reader.onload = () => {
            //console.log("reader.result= " + reader.result);
            //console.log("Loaded " + chosenFile.name);
            console.log("Publish data from file: size=" + reader.result.byteLength);
            msg.payload = napicli.util.uint8ArrayToB64(new Uint8Array(reader.result));
            message.service.publish(msg, afterPublish);
        };

        // Read in the image file as byte buffer.
        reader.readAsArrayBuffer(chosenFile);
    }
}



/*
 * Postlude to a publish
 */
function afterPublish(msg) {
    //console.log("AfterPublish "+ JSON.stringify(msg));

    // Empty the payload and desc
    clearPubInputs();
    clearPubDesc();
    removeDescAllRows(document.getElementById("pub-desc-tab"));

    // Add the msg to the HTML publish list
    addPubListElt(msg);

    // Revalidate the button
    activatePubButton(true);

}



function clickAddPubDescRow() {
   addPubDescRow();
   document.getElementById("pub-input-key").focus();
}


function clickAddSubsDescRow() {
    addSubsDescRow();
    document.getElementById("subs-input-key").focus();
}




/*
 * Action associated with the Subscribe button
 */
function clickSubscribe() {

    // Checks if the descriptor is unfinished
    if (document.getElementById("subs-input-key").value !== "") {
        clickAddSubsDescRow();
        //console.log("Descriptor completed with the input line");
    }

    // The current subscription descriptor should not be empty
    if (Object.keys(subsDesc).length === 0) {
        alert("Cannot make a subscription from an empty descriptor");
        return;
    }

    // Make the subscription, and get the created subscription key
    message.service.subscribe(subsDesc, addRecepListElt, afterSubscribe);
}



/*
 * Postlude to a subscribe
 */
function afterSubscribe(skey) {
    console.log("New subscription : "+skey);

    // Add the subscription to the displayed list
     addSubsListElt(skey, subsDesc);

    // Remove the rows of the descriptor table
    removeDescAllRows(document.getElementById("subs-desc-tab"));

    // Clear the current subscription descriptor
    clearSubsDesc();

    clearSubsInputs();

}




function clickHamburger() {
    if (menuVisible())
      hideMenu();
    else
      showMenu();
}

// A click outside the hamburger hides the menu
window.onclick = function(event) {
    if (!event.target.matches(".hamburger")) {
      hideMenu();
   }
};


function menuVisible() {
    return document.getElementById("main-menu").style.display === "block";
}

function showMenu() {
  document.getElementById("main-menu").style.display = "block";
}

function hideMenu() {
   document.getElementById("main-menu").style.display = "none";
}

function clickConnect() {
    let server = document.getElementById("connect-address").value.trim();
    let indexSemiColon = server.indexOf(":");
    if (indexSemiColon === -1) return;
    window.localStorage.setItem("server_host", server.substring(0, indexSemiColon));
    window.localStorage.setItem("server_port", server.substring(indexSemiColon+1));
    window.location.reload();
}


function clickPubCollapse() {
    toggleButtonText(this);
    toggleCollapse([document.getElementById("pub-content"),
                    document.getElementById("pub-button")]
                  );
}


function clickSubsCollapse() {
    toggleButtonText(this);
    toggleCollapse([document.getElementById("subs-content"),
                    document.getElementById("subs-button")]
                  );
}


function clickRecepCollapse() {
    toggleButtonText(this);
    toggleCollapse(document.getElementById("recep-content"));
}



function toggleButtonText(btn) {
    if (btn.firstChild.data === "▲") {
        btn.firstChild.data = "▼";
    }
    else {
         btn.firstChild.data = "▲";
    }
}



// Used to memorize the states of the CSS display property of collapsible sections
var savedDisplays = {};

function toggleCollapse(elements) {
    elements = elements.length ? elements : [elements];

    for (let i=0; i<elements.length; i++) {
        let elt = elements[i];
         let computedDisplay = window.getComputedStyle(elt, null).getPropertyValue('display');
        if (computedDisplay === "none") {
            elt.style.display = savedDisplays[elt.id];
        } else {
            savedDisplays[elt.id] = computedDisplay;
            elt.style.display = "none";
        }
    }

}


/*
 * Activate or deactivate buttons for publishing and subscribing
 */
function activatePubsubButtons(active) {
    activatePubButton(active);
    activateSubButton(active);
}

function activatePubButton(active) {
    document.getElementById("pub-button").disabled = ! active;
}

function activateSubButton(active) {
    document.getElementById("subs-button").disabled = ! active;
}


// =======================================================================


function addPubDescRow() {
  addDescRow(document.getElementById("pub-input-key"),
            document.getElementById("pub-input-value"),
            pubDesc,
            document.getElementById("pub-desc-tab")
            );
}

function addSubsDescRow() {
    addDescRow(document.getElementById("subs-input-key"),
            document.getElementById("subs-input-value"),
            subsDesc,
            document.getElementById("subs-desc-tab")
            );
}



/*
 * Adds a row both in a descriptor object and in an HTML div.
 * The source of the key, value are two HTML inputs.
 */
function addDescRow(keyInput, valueInput, desc, div) {
    //console.log('addDescRow ' + keyInput.value + "  " + valueInput.value + "  " + JSON.stringify(desc) + "  "+ div);

    let newKey = keyInput.value.trim();
    let newValue = valueInput.value.trim();

    if (newKey === "") {
      alert("Please type in a key before adding a new one");
        return;
    }

    // Update the descriptor
    let ok = desc.setAttribute(newKey, newValue);
    if (! ok) {
       alert("Key already present");
        return;
    }

    // Append the couple to the pub desc element
    let row = document.createElement("div");
    row.setAttribute("class", "desc-row");

    let col1 = document.createElement("div");
    col1.innerHTML += newKey;
    col1.setAttribute("class", "keycell");
    row.appendChild(col1);

    let col2 = document.createElement("div");
    col2.innerHTML += newValue;
    col2.setAttribute("class", "valuecell");
    row.appendChild(col2);

    let buttonNode = document.createElement("button");
    buttonNode.setAttribute("class", "buttoncell");
    let textNode = document.createTextNode("–");
    buttonNode.appendChild(textNode);
    buttonNode.onclick = function () { removeDescRow(newKey, desc, row);};
    buttonNode.appendChild(textNode);
    row.appendChild(buttonNode);

    div.appendChild(row);

    // Clear the input elements
    keyInput.value="";
    valueInput.value="";
  }



/*
 * Remove a couple key/value in a descriptor
 * and the corresponding elt
*  @param {string} key
*  @param {Descriptor} desc
 * @param {Element} elt
 */
function removeDescRow(key, desc, elt) {
    //console.log("removeDescRow for key:" + key);
    elt.remove();
    delete(desc[key]);
}

/*
 * Removes all the rows of a desc element
 */
function removeDescAllRows(elt) {
    elt.innerHTML = "";
}





function clearPubInputs() {
    document.getElementById("pub-input-key").value = "";
    document.getElementById("pub-input-value").value = "";
    document.getElementById("pub-textpayload-input").value = "";
    document.getElementById("pub-file").value = "";
}

function clearSubsInputs() {
    document.getElementById("subs-input-key").value = "";
    document.getElementById("subs-input-value").value = "";
}


/*
 * Adds a div (a list-elt) at the beginning of the subs-list. This div contains
 *  - a pseudo-table filled with the couples of a descriptor
 *  - an unsubscribe button
 * @param {String} skey
 * @param {Descriptor} desc
 */
function addSubsListElt(skey, desc) {
    //console.log("addSubsListElt "+ skey + " "+ desc.toJson());

    let eltNode = document.createElement("div");
    eltNode.setAttribute("class", "list-elt");

    // Fill the table and add it to the div
    let eltTabNode = document.createElement("div");
    eltTabNode.setAttribute("class", "list-elt-tab");

    for (let [k,v] of Object.entries(desc)) {
            // Append the couple to the pub desc element
            let row = document.createElement("div");
            row.setAttribute("class", "desc-row");

            let col1 = document.createElement("div");
            col1.innerHTML += k;
            col1.setAttribute("class", "keycell");
            row.appendChild(col1);

            let col2 = document.createElement("div");
            col2.innerHTML += desc[k];
            col2.setAttribute("class", "valuecell");
            row.appendChild(col2);

            eltTabNode.appendChild(row);
   }
    eltNode.appendChild(eltTabNode);

    // Add to the div the unsusbcribe button associated with this table
    let buttonNode = document.createElement("button");
    buttonNode.setAttribute("class", "list-elt-button");
    let textNode = document.createTextNode("–");
    buttonNode.appendChild(textNode);
    buttonNode.onclick = function () {clickUnsubscribe(skey, eltNode);};
    eltNode.appendChild(buttonNode);

    // Insert the div into the list
    insertFirst(eltNode, document.getElementById("subs-list"));
}



/*
 * Action associated with the Unsubscribe button
 *
 * @return {undefined}
 */
function clickUnsubscribe(skey, elt) {
    //console.log("clickUnsubscribe  key="+skey + "  elt="+elt);
    message.service.unsubscribe(skey,
        () => { removeListElt(elt); }
    );
}


/*
 * Adds a message to the HTML reception list
 * @param {Message} msg
 */
function addRecepListElt(msg) {
    addMessageListElt(msg, document.getElementById("recep-list"));
}


/*
 * Adds a message to the HTML publication list
 * @param {Message} msg
 */
function addPubListElt(msg) {
    addMessageListElt(msg, document.getElementById("pub-list"));
}


/*
 * Adds a div (a list-elt) at the beginning of a message list. This div contains
 * information taken from a Message object:
 *  - a div that contains a date
 *  - a table filled with the couples of a descriptor
 *  - a div that contains the text of the message, or a button to open a file
 * @param {Message} msg
 * @param {Element} listElt  the message list as an HTML Element
 */
function addMessageListElt(msg, listElt) {
    //console.log("addRecepListElt desc="+ JSON.stringify(msg.desc));
    //console.log("addRecepListElt payload="+ msg.payload);

    let eltNode = document.createElement("div");
    eltNode.setAttribute("class", "recep-list-elt");

    let dateNode = document.createElement("div");
    let textNode = document.createTextNode(msg.date);
    dateNode.setAttribute("class", "date");
    dateNode.appendChild(textNode);
    eltNode.appendChild(dateNode);

    // Fill the table and add it to the div
    let eltTabNode = document.createElement("div");
    eltTabNode.setAttribute("class", "recep-list-tab");
    for (let [k, v] of Object.entries(msg.desc)) {
        if (! k.startsWith("_")) {
            // Append the couple to the pub desc element
            let row = document.createElement("div");
            row.setAttribute("class", "desc-row");

            let col1 = document.createElement("div");
            col1.innerHTML += k;
            col1.setAttribute("class", "keycell");
            row.appendChild(col1);

            let col2 = document.createElement("div");
            col2.innerHTML += v;
            col2.setAttribute("class", "valuecell");
            row.appendChild(col2);

            eltTabNode.appendChild(row);
        }
    }
    eltNode.appendChild(eltTabNode);


    let payloadNode = document.createElement("div");

    if (msg.ptype === "text") {
       payloadNode.setAttribute("class", "recep-payload-text");
       payloadNode.innerHTML = napicli.util.b64ToString(msg.payload);
    }
    else if (msg.ptype === "file") {
        let linkNode = document.createElement("a");

        let b64 = napicli.util.b64ToUint8Array(msg.payload);
        let blob = new Blob([b64], {type: msg.desc._webopp_pmime});

        linkNode.href = window.URL.createObjectURL(blob);
        linkNode.download= msg.desc._webopp_file;
        linkNode.text = ellipside(msg.desc._webopp_file, 20);

        let buttonSaveNode =  document.createElement("button");
        buttonSaveNode.setAttribute("type", "button");
        buttonSaveNode.setAttribute("class", "file-button");
        buttonSaveNode.appendChild(linkNode);

        payloadNode.setAttribute("class", "recep-payload-file");
        payloadNode.appendChild(buttonSaveNode);
    }

    eltNode.appendChild(payloadNode);

    insertFirst(eltNode, listElt);
}



 /*
  * Shortens too long strings by replacing the middle of the string by ellipsis.
  * Short-enough strings are returned unchanged.
  * @param {type} str
  * @param {type} maxlen the number of characters preserved from the original string
  *               (hence the return string has at most maxlen +1 characaters)
  * @return {Function}
  */
 function ellipside(str, maxlen) {
     let strlen = str.length;
     if ((strlen - maxlen) < 0) return str;
     let firstpartlen = maxlen/2;
     let lastpartlen = firstpartlen;
     if ((strlen % 2) !== 0) firstpartlen++;
     return str.substring(0, firstpartlen) + "…" + str.substring(strlen-lastpartlen);
 }



/*
 * Inserts an element as the first child of a parent
 * @param {Element} elt
 * @param {Element} parent
 * @return {undefined}
 */
function insertFirst(elt, parent) {
    if (parent.hasChildNodes()) {
        parent.insertBefore(elt, parent.firstElementChild);
    }
    else {
        parent.appendChild(elt);
    }
}


/*
 * Removes an element from a HTML list
 * @param {Element} elt
 * @return {undefined}
 */
function removeListElt(elt) {
    elt.remove();
}