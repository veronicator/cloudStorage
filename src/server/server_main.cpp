#include "server.h"

int main() {
    Server* server = new Server();

    fd_set master;
    fd_set read_set;
    int fd_max;
    int new_sd;

    //set to zero
    FD_ZERO(&master);
    FD_ZERO(&read_set);

    // add listener to master set
    FD_SET(server->getListener(), &master);     // add listener to set master
    fd_max = server->getListener();
    
    // select sockets ready 

    // thread
    list<pthread_t> threads;
    while(true) {
        read_set = master;
        int new_sd = server->acceptConnection();
        if(new_sd < 0)
            continue;
        pthread_t client_thread;
        ThreadArgs* args = new ThreadArgs(server, new_sd);
        cout << "pthread_create" << endl;
        if(pthread_create(&client_thread, NULL, &client_thread_code, (void*)args) != 0)
            handleErrors("thread_create failed");
        cout << "new pthread_created" << endl;
        threads.push_back(client_thread);
        pthread_detach(client_thread);  // con detach non serve fare il join finale (controllare funzioni bene)
        /*cout << threads.size() << " empty" << endl;
        void* retval;
        if(pthread_join(client_thread, &retval) != 0) {
            //printf("retval %s\n", *(char*)retval);
            cout << " terminato" << endl;
        }*/
    }

    //server->joinThread();
    /*
    while(!threads.empty()) {
        pthread_t t = threads.front();
        pthread_join(threads.front(), NULL);
        threads.pop_front();
    }*/
    return 0;
}