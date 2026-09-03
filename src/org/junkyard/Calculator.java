package org.junkyard;

import java.awt.Frame;
import java.awt.Panel;
import java.awt.Button;
import java.awt.Label;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.Font;
import java.awt.Color;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

/**
 * CHAIN "calc" payload -- a working AWT calculator, rendered on the Dreamcast by
 * arbitrary code we delivered through the Eden service-subscription RCE (Bug #1).
 * Pure PersonalJava 1.1.8 / AWT 1.1 (no Swing, no anonymous inner classes) so it
 * compiles to class v45.3 against the device runtime and runs in the browser VM.
 *
 * The calculator itself is the proof: we are running our own GUI program on a 1999
 * game console, with no memory corruption -- just the design flaw.
 */
public class Calculator extends Frame implements ActionListener, Runnable {

    private Label display = new Label("0", Label.RIGHT);
    private double acc = 0.0;
    private String op = "";
    private boolean fresh = true;

    public Calculator() {
        super("PWNED :: Calculator");
        setBackground(new Color(20, 20, 24));
        setForeground(new Color(120, 255, 120));
        setLayout(new BorderLayout(4, 4));

        display.setFont(new Font("Monospaced", Font.BOLD, 28));
        display.setBackground(new Color(8, 12, 8));
        display.setForeground(new Color(120, 255, 120));
        add(display, BorderLayout.NORTH);

        Panel grid = new Panel();
        grid.setLayout(new GridLayout(4, 4, 4, 4));
        String[] keys = { "7","8","9","/",
                          "4","5","6","*",
                          "1","2","3","-",
                          "0","C","=","+" };
        for (int i = 0; i < keys.length; i++) {
            Button b = new Button(keys[i]);
            b.setFont(new Font("SansSerif", Font.BOLD, 22));
            b.setBackground(new Color(30, 34, 42));
            b.setForeground(new Color(224, 224, 224));
            b.addActionListener(this);
            grid.add(b);
        }
        add(grid, BorderLayout.CENTER);

        // The browser's native HTML view sits ON TOP of a service's AWT window, so a plain
        // setVisible() renders behind the (cached) page. DoomShell solves this by repeatedly
        // calling toFront(); do the same -- show, raise, and keep raising on a daemon thread.
        setSize(320, 340);
        setVisible(true);
        try { toFront(); requestFocus(); } catch (Throwable t) {}
        Thread keep = new Thread(this);
        keep.setDaemon(true);
        keep.start();
    }

    /** keep the calculator on top of the browser's HTML renderer. */
    public void run() {
        for (int i = 0; ; i++) {
            try { Thread.sleep(600); } catch (Throwable t) {}
            try { toFront(); if (i < 3) requestFocus(); } catch (Throwable t) {}
        }
    }

    public void actionPerformed(ActionEvent e) {
        String k = e.getActionCommand();
        char c = k.charAt(0);
        if (c >= '0' && c <= '9') {
            if (fresh) { display.setText(k); fresh = false; }
            else { display.setText(display.getText() + k); }
        } else if (k.equals("C")) {
            acc = 0.0; op = ""; fresh = true; display.setText("0");
        } else if (k.equals("=")) {
            compute(); op = ""; fresh = true;
        } else {
            compute(); op = k; fresh = true;
        }
    }

    private void compute() {
        double v = 0.0;
        try { v = Double.valueOf(display.getText()).doubleValue(); }   // 1.1-safe (no parseDouble)
        catch (Exception ex) { v = 0.0; }
        if (op.equals("+")) acc = acc + v;
        else if (op.equals("-")) acc = acc - v;
        else if (op.equals("*")) acc = acc * v;
        else if (op.equals("/")) acc = (v != 0.0) ? acc / v : 0.0;
        else acc = v;
        if (acc == Math.floor(acc) && !Double.isInfinite(acc))
            display.setText(String.valueOf((long) acc));
        else
            display.setText(String.valueOf(acc));
    }
}
