
$(document).ready(function(){
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var text_received = [];

    //receive details from server
    socket.on('newtext', function(msg) {
        console.log("Received text" + msg.text);
        //maintain a list of ten numbers
        //if (text_received.length >= 10){
         //   text_received.shift()
        //}
        text_received.push(msg.text);
        numbers_string = '';
        numbers_string = '<p>' + text_received + '</p>';
        $('#log').html(numbers_string);
    });

});