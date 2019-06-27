"""
Demo Flask application to test the operation of Flask with socket.io

Aim is to create a webpage that is constantly updated with random numbers from a background python process.

30th May 2014

===================

Updated 13th April 2018

+ Upgraded code to Python 3
+ Used Python3 SocketIO implementation
+ Updated CDN Javascript and CSS sources

"""




# Start with a basic flask app webpage.
from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context, request
from threading import Thread, Event
import select, socket, queue
import logging
import argparse
from os import _exit, environ
from uuid import uuid4
from time import sleep


__author__ = 'slynn'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

# turn the flask app into a socketio app
socketio = SocketIO(app)

# random number Generator Thread
thread = Thread()
thread_stop_event = Event()

LOG_FORMAT = "%(asctime)s %(filename)s:%(lineno)-3d %(levelname)s %(message)s"

FORMATTER = logging.Formatter(LOG_FORMAT)

CONSOLE_HANDLER = logging.StreamHandler()
CONSOLE_HANDLER.setFormatter(FORMATTER)

LOGGER = logging.getLogger()
LOGGER.addHandler(CONSOLE_HANDLER)
LOGGER.setLevel('DEBUG')

global SEND_message, message_queues, outputs, object_dictionary, SERVER_IP, SERVER_PORT, FROM_PATH, TO_PATH, message
SEND_message = None
message_queues = {}
outputs = []
object_dictionary = {}


class RandomThread(Thread):
    def __init__(self):
        self.delay = 1
        super(RandomThread, self).__init__()
        self.browser_queue = []
        self.error_response = False
        self.success_checkbox = True
        self.failure_checkbox = False
        self.report_checkbox = True
    # def randomNumberGenerator(self):
    #     """
    #     Generate a random number every 1 second and emit to a socketio instance (broadcast)
    #     Ideally to be run in a separate thread?
    #     """
    #     #infinite loop of magical random numbers
    #     print("Making random numbers")
    #     while not thread_stop_event.isSet():
    #         number = round(random()*10, 3)
    #         print(number)
    #         socketio.emit('newnumber', {'number': number}, namespace='/test')
    #         sleep(self.delay)

    def update_browser_queue(self, content):
        logging.debug('Adding to browser queue.')
        self.browser_queue.append(content)

    def update_browser(self):
        data = ''

        if self.browser_queue:
            data = '\r\n'.join(self.browser_queue)
            data = data.replace('\r\n', '<br>')
            logging.debug('Emit to browser using socketio.')
            socketio.emit('newtext', {'text': data}, namespace='/test')

            self.browser_queue = []


    def run(self):
        self.server_content()

    def send_msg(self):
        """ Formats and puts the MSRP message into the queue for sending to the server. """

        logging.debug(f'Sucess report status: {self.success_checkbox}')
        logging.debug(f'Sucess report status: {self.failure_checkbox}')
        logging.debug('Creating new message to send.')
        global SEND_message, to_path, from_path, message
        # to_path = e1.get().rstrip()
        # from_path = e2.get().rstrip()
        # message = e3.get("1.0", tk.END).rstrip()
        transaction_id = uuid4()
        transaction_id = str(transaction_id)[:15]
        transaction_id = transaction_id.replace('-', '')
        message_id = uuid4()
        message_id = str(message_id)[:15]
        message_id = message_id.replace('-', '')
        message_length = (len(message))
        content_type = 'text/plain'

        SEND_message = f'MSRP {transaction_id} SEND\r\n'
        SEND_message += f'To-Path: {to_path}\r\n'
        SEND_message += f'From-Path: {from_path}\r\n'
        SEND_message += f'Message-ID: {message_id}\r\n'
        if self.report_checkbox:
            if self.success_checkbox:
                SEND_message += f'Success-Report: yes\r\n'
            else:
                SEND_message += f'Success-Report: no\r\n'
            if self.failure_checkbox:
                SEND_message += f'Failure-Report: yes\r\n'
            else:
                SEND_message += f'Failure-Report: no\r\n'
        SEND_message += f'Byte-Range: 1-{message_length}/{message_length}\r\n'
        SEND_message += f'Content-Type: {content_type}\r\n'
        SEND_message += '\r\n'
        SEND_message += f'{message}\r\n'
        SEND_message += f'-------{transaction_id}$\r\n'

        for aQueue in message_queues:
            logging.debug('Adding new message to output queue.')
            message_queues[aQueue].put(SEND_message.encode('utf8'))
            outputs.append(aQueue)

    def send_report(self, message_object):
        """ Formats and puts the MSRP REPORT message into the output gueue. """

        transaction_id = uuid4()
        transaction_id = str(transaction_id)[:15]
        transaction_id = transaction_id.replace('-', '')

        SEND_message = f'MSRP {transaction_id} REPORT\r\n'
        SEND_message += f'To-Path: {message_object[4]}\r\n'
        SEND_message += f'From-Path: {message_object[3]}\r\n'
        SEND_message += f'Message-ID: {message_object[5]}\r\n'
        SEND_message += f'Byte-Range: 1-{message_object[6]}/{message_object[6]}\r\n'
        SEND_message += f'Status: 000 200 OK\r\n'
        SEND_message += f'-------{transaction_id}$\r\n'

        for aQueue in message_queues:
            logging.debug('Adding new message to output queue.')
            message_queues[aQueue].put(SEND_message.encode('utf8'))
            outputs.append(aQueue)

    def send_200_response(self, message_object, response_code):
        """ Formats and puts a 200 response into the output queue. """

        if response_code == '200':
            SEND_message = f'MSRP {message_object[0]} 200 OK\r\n'
        else:
            SEND_message = f'MSRP {message_object[0]} 400 Bad Request\r\n'

        SEND_message += f'To-Path: {message_object[4]}\r\n'
        SEND_message += f'From-Path: {message_object[3]}\r\n'
        SEND_message += f'-------{message_object[0]}$\r\n'

        for aQueue in message_queues:
            logging.debug('Adding 200 response to output queue.')
            message_queues[aQueue].put(SEND_message.encode('utf8'))
            outputs.append(aQueue)

        sleep(1)
        logging.debug(f'Success status: {message_object[8]}')
        if response_code == '200':
            if message_object[8] == 'yes':  # check success report request
                logging.debug("Success report request true, send REPORT")
                self.send_report(message_object)

    def message_decode(self, content):
        """ Decodes a received message and populates the transaction object list. """

        transaction_id = None
        request_type = None
        response_code = None
        to_path = None
        from_path = None
        message_id = None
        byte_range = None
        content_type = None
        success_report = None
        failure_report = None
        body = None
        decode = True

        try:
            for line in content.splitlines():
                if line[:7] == "-------":
                    pass
                elif line[:4] == "MSRP":
                    scratch = line.split(" ")
                    transaction_id = scratch[1].strip()
                    if scratch[2].strip() == "SEND":
                        request_type = "SEND"
                    elif scratch[2].strip() == "REPORT":
                        request_type = "REPORT"
                    else:
                        response_code = scratch[2]
                else:
                    scratch = line.split(":")
                    logging.debug(f'Print line debug: {scratch}')
                    if scratch[0] == "To-Path":
                        to_path = scratch[1].strip()
                    elif scratch[0] == "From-Path":
                        from_path = scratch[1].strip()
                    elif scratch[0] == "Message-ID":
                        message_id = scratch[1].strip()
                    elif scratch[0] == "Content-Type":
                        content_type = scratch[1].strip()
                    elif scratch[0] == "Byte-Range":
                        byte_range = scratch[1].split("/")[1].strip()
                    elif scratch[0] == "Success-Report":
                        success_report = scratch[1].strip()
                        logging.debug(f'Success report decoded as: {success_report}')
                    elif scratch[0] == "Failure-Report":
                        failure_report = scratch[1].strip()
                    elif scratch[0] == "\r\n":
                        pass
                    else:
                        body = scratch[0].strip()
        except IndexError:
            pass
        except ValueError:
            logging.error("Message decode failure.")
            logging.error(content)
            decode = False

        transaction_object = [
            transaction_id,
            request_type,
            response_code,
            to_path,
            from_path,
            message_id,
            byte_range,
            content_type,
            success_report,
            failure_report,
            body,
            decode
        ]
        logging.debug("Message decode complete.")

        return transaction_object

    def server_content(self):
        """ Starts and manages main TCP socket connection to the server. """

        global SEND_message, message_queues, outputs, SERVER_IP, SERVER_PORT
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.connect((SERVER_IP, SERVER_PORT))
        logging.debug(f"connected to {SERVER_IP}:{SERVER_PORT}")

        inputs = [client]
        outputs = []
        client.setblocking(False)
        message_queues[client] = queue.Queue()

        while inputs:
            logging.debug('Socket wait.')
            readable, writable, exceptional = select.select(
                inputs, outputs, inputs, 1)
            logging.debug('Socket go.')
            data = ""
            decoded_data = ""
            self.update_browser()
            for s in readable:
                logging.debug('Reading data next.')
                while data != b'$':
                    try:
                        data = s.recv(1)
                        decoded_data += data.decode("utf-8")
                    except (BlockingIOError, socket.error):
                        logging.debug('Error occurred, continue.')
                        sleep(0.5)
                        break

                self.update_browser_queue(decoded_data)
                logging.debug('Done reading data.')

                decoded_message = self.message_decode(decoded_data)
                if decoded_message[1] == "SEND":
                    if self.error_response:
                        self.send_200_response(decoded_message, '400')
                    else:
                        self.send_200_response(decoded_message, '200')

            for s in writable:
                logging.debug('Sending data next.')

                try:
                    next_msg = message_queues[s].get_nowait()
                except queue.Empty:
                    outputs.remove(s)
                else:
                    s.send(next_msg)
                    self.update_browser_queue(next_msg.decode('utf8'))
                    outputs.remove(s)
                    logging.debug('Data sent.')

            for s in exceptional:
                logging.debug('Exception handling.')
                inputs.remove(s)
                if s in outputs:
                    outputs.remove(s)
                s.close()
                del message_queues[s]


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/submit', methods=['POST'])
def submit():
    global to_path, from_path, message

    logging.debug('Entered submit function.')
    if request.form['text_msg']:
        to_path = request.form['msrp_to_path']
        from_path = request.form['msrp_from_path']
        message = request.form['text_msg']
        logging.debug(f'Form data: {to_path}, {from_path}, {message}')
        thread.send_msg()

    return render_template('index.html')


@socketio.on('connect', namespace='/test')
def test_connect():
    # need visibility of the global thread object
    global thread
    print('Client connected')

    #Start the random number generator thread only if the thread has not been started before.
    if not thread.isAlive():
        print("Starting Thread")
        thread = RandomThread()
        thread.start()


@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == '__main__':

    global SERVER_IP, SERVER_PORT, FROM_PATH, TO_PATH

    parser = argparse.ArgumentParser(description='MSRP GUI client.')
    parser.add_argument('-t', help='URL used in MSRP To Path', required=True)
    parser.add_argument('-f', help='URL used in MSRP From Path', required=True)
    parser.add_argument('-i', help='Target connection IP address', required=False)
    parser.add_argument('-p', help='Target connection port', required=False)
    args = parser.parse_args()

    if args.i:
        SERVER_IP = args.i
    elif 'TEST_HOST_IP' in environ:
        SERVER_IP = environ('TEST_HOST_IP')
    else:
        SERVER_IP = '127.0.0.1'

    if args.p:
        SERVER_PORT = args.p
    elif 'TEST_HOST_PORT' in environ:
        SERVER_PORT = environ('TEST_HOST_PORT')
    else:
        SERVER_PORT = 10000

    FROM_PATH = args.f
    TO_PATH = args.t

    socketio.run(app)
