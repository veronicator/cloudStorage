#include "server.h"

int main() {
    Server* server = new Server();

    fd_set master;
    fd_set read_set;    

    //set to zero
    FD_ZERO(&master);
    FD_ZERO(&read_set);

    // add listener to master set
    FD_SET(server->getListener(), &master);     // add listener to set master

    // thread
    list<pthread_t> threads;
    try {
        while(true) {
            read_set = master;
            int new_sd = server->acceptConnection();
            if(new_sd < 0)
                continue;

            pthread_t client_thread;
            ThreadArgs* args = new ThreadArgs(server, new_sd);
            cout << "pthread creation" << endl;
            if(pthread_create(&client_thread, NULL, &client_thread_code, (void*)args) != 0) {
                perror("thread_create failed");
                continue;
            }
            cout << "new pthread_created" << endl;
            threads.push_back(client_thread);
            pthread_detach(client_thread);  // con detach non serve fare il join finale (controllare funzioni bene)
        }
    } catch (const exception &e) {
        cout << "Exit due to an error:\n" << endl;
        cerr << e.what() << endl;
        return 0;
    }

    delete server;
    return 0;
}