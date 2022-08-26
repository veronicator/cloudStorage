#include "client.h"

// TODO
int main(int argc, char* argv[]) {

    if(argc != 2) {
        cout << "required parameters: <server ip> " << endl;    // <server port>
        return 1;
    }
    char command = '!';
    // socket: server ip

    string usr;
    // readUsername(usr);
    readInput(usr, MAX_NAME_SIZE, "Please, insert your username: ");
    Client* client = new Client(usr, argv[1]);
    if(!client->authentication())
        handleErrors("Authentication failed");
    // stampa lista utenti

    string msg_input;
    bool ok = false;
    
    do {
        client->showCommands();
        readInput(msg_input, MAX_COMMAND_SIZE, "Insert command"); 
        if(msg_input[0] != command) 
            cout << "Command not recognized" << endl;
        else
            ok = client->handlerCommand(msg_input);
    } while(msg_input[0] != command || !ok);
    // per ogni digital signature, legge la chiave privata ?
    // cerca file usr.pem -> se non esiste => exit/return
    
}