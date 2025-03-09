package com.mars.demoOkata;

import java.util.Date;

public class Message {
    public Date date = new Date();
    public String text;

    Message(String text) {
        this.text = text;
    }
}
