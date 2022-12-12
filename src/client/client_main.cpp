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
    Client *client = nullptr;
    try {
        // readUsername(usr);
        readInput(usr, MAX_NAME_SIZE, "Please, insert your username: ");
        client = new Client(usr, argv[1]);
        if(!client->authentication()) {
            cerr << "Authentication failed" << endl;
            delete client;
            exit(EXIT_FAILURE);
        }
        // stampa lista utenti

        string msg_input;
        bool ok = true;
        
        while (ok) {
            client->showCommands();
            readInput(msg_input, MAX_COMMAND_SIZE, "Insert command"); 
            if(msg_input[0] != command) {
                cout << "Command not recognized" << endl
                    << "Commands start with '!'" << endl;
            } else
                ok = client->handlerCommand(msg_input);
        }

    } catch (const exception &e) {
        cout << "Exit due to an error:\n" << endl;
        cerr << e.what() << endl;
        delete client;
        return 0;
    }
    delete client;
    cout << "end client main" << endl;
    return 0;
}