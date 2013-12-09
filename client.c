/*
 * Client for distributed bruteforce
 *
 * compile with :
 *   gcc -Wall -O2 -o client client.c
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>


volatile int child_alive;

static void child_dead(int signo)
{
    child_alive = 0;
}

void password_by_index(unsigned long long index, char* password, const char* charset, unsigned int charset_length)
{
    unsigned int i = 0;

    while(1)
    {
        password[i++] = charset[index % charset_length];
        index /= charset_length;

        if(index == 0L) break;
        index--;
    }

    password[i] = '\0';
}


void next_password(char *password, const char* charset, unsigned int charset_length, const char *charset_next_char)
{
    unsigned int i = 0;

    while(password[i] != '\0' && password[i] == charset[charset_length - 1])
    {
        password[i++] = charset[0];
    }

    if(password[i] == '\0')
    {
        password[i++] = charset[0];
        password[i] = '\0';
    }
    else
    {
        password[i] = charset_next_char[(int)password[i]];
    }
}
 

int main(int argc, char **argv)
{
    extern char* __progname;
    char *host, *command;
    int port;
    char charset[256], password[80], charset_next_char[256];
    unsigned int i;
    char response;
    unsigned int charset_length;
    unsigned int packet_size;
    unsigned long long current_packet;

    /* network */
    int sock;
    struct hostent *hostinfo = NULL;
    struct sockaddr_in sin = { 0 };

    /* subprocess */
    int fork_pid;
    int pipe_in[2];
    int pipe_out[2];
    FILE* command_in;
    struct sigaction action;

    /*******************
     * Parse arguments *
     *******************/
    if(argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
    {
        printf("usage: %s [-h] host port command\n", __progname);
        printf("\n");
        printf("Client for distributed bruteforce\n");
        printf("\n");
        printf("optional arguments:\n");
        printf("  -h, --help     show this help message and exit\n");
        exit(0);
    }

    /* error messages */
    if(argc < 4)
    {
        printf("usage: %s [-h] host port command\n", __progname);
        printf("%s: error: too few arguments\n", __progname);
        exit(1);
    }

    host = argv[1];
    port = atoi(argv[2]);
    command = argv[3];


    /************************
     * Connection to server *
     ************************/

    printf("Connection to server %s:%d\n", host, port);

    /* create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock == -1)
    {
        fprintf(stderr, "error: unable to create a socket\n");
        exit(1);
    }

    /* dns lookup */
    hostinfo = gethostbyname(host);
    if(hostinfo == NULL)
    {
        fprintf(stderr, "error: unknown host %s\n", host);
        exit(1);
    }

    sin.sin_addr = *(struct in_addr*) hostinfo->h_addr;
    sin.sin_port = htons(port);
    sin.sin_family = AF_INET;

    /* connection to host:port */
    if(connect(sock, (struct sockaddr*) &sin, sizeof(struct sockaddr)) == -1)
    {
        fprintf(stderr, "error: unable to connect to %s:%d\n", host, port);
        exit(1);
    }

    /* reading charset */
    if(recv(sock, charset, sizeof(charset), 0) < 0)
    {
        fprintf(stderr, "error: failed to read charset from server\n");
        close(sock);
        exit(1);
    }
    charset_length = strlen(charset);
    printf("charset: %s\n", charset);

    /* computing charset_next_char */
    for(i = 0; i < charset_length; i++)
    {
        charset_next_char[(int)charset[i]] = charset[i + 1];
    }

    /* reading packet_size */
    if(recv(sock, (char*)&packet_size, sizeof(packet_size), 0) < 0)
    {
        fprintf(stderr, "error: failed to read packet_size from server\n");
        close(sock);
        exit(1);
    }
    printf("packet size: %d\n", packet_size);


    /*********************
     * Manage subprocess *
     *********************/

    if(pipe(pipe_in) < 0 || pipe(pipe_out) < 0)
    {
        fprintf(stderr, "error: failed to make pipe\n");
        close(sock);
        exit(1);
    }

    fork_pid = fork();

    if(fork_pid < 0)
    {
        fprintf(stderr, "error: failed to fork\n");
        close(sock);
        exit(1);
    }
    else if(fork_pid == 0) /* child */
    {
        /*close(1); Close current stdout. */
        /*dup(command_out[1]);  Make stdout go to write end of pipe. */

        close(0); /* Close current stdin. */
        dup(pipe_in[0]); /* Make stdin come from read end of pipe. */

        close(pipe_in[1]);
        /*close(command_out[0]); */
        execvp(command, argv + 3);
        exit(1);
    }

    child_alive = 1;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = child_dead;
    if(sigaction(SIGCHLD, &action, NULL) == -1)
    {
        fprintf(stderr, "error: an error occured when setting a signal handler\n");
        close(sock);
        exit(1);
    }
    command_in = fdopen(pipe_in[1], "w");

    /*************
     * Main loop *
     *************/

    while(child_alive)
    {
        /* receive work */
        current_packet = 0L;
        if(recv(sock, (char*)&current_packet, sizeof(current_packet), 0) < 0)
        {
            fprintf(stderr, "error: failed to receive next packet from server\n");
            close(sock);
            exit(1);
        }

        printf("received work: %llu\n", current_packet);

        /* doing work */
        password_by_index(current_packet, password, charset, charset_length);

        for(i = 0; i < packet_size; i++)
        {
            fprintf(command_in, "%s\n", password);
            next_password(password, charset, charset_length, charset_next_char);

            if(!child_alive)
                break;
        }

        /* send response */
        response = 0;
        if(send(sock, &response, 1, 0) < 0)
        {
            fprintf(stderr, "error: failed to send response to server\n");
            close(sock);
            exit(1);
        }
    }

    printf("passphrase found !\n");

    /* success ! */
    response = 1;
    if(send(sock, &response, 1, 0) < 0)
    {
        fprintf(stderr, "error: failed to send response to server\n");
        close(sock);
        exit(1);
    }

    close(sock);
    return 0;
}
