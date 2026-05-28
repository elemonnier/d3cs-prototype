/* *****************************************************************************
 * Copyright (c) IRISA Laboratory, 
 * Universite Bretagne Sud, France
 * <http://www-casa.irisa.fr/lepton>
 *
 * This file is part of LEPTON.
 * 
 * LEPTON is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software 
 * Foundation, either version 3 of the License, or any later
 * version.
 * 
 * LEPTON is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Lepton.  If not, see <http://www.gnu.org/licenses/>.
 * ****************************************************************************/
package casa.lepton.ui;

import casa.lepton.console.OppNetConsole;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;

/**
 * A panel that looks like a pseudo terminal. At the panel creation, a TCP
 * session is opened with the {@link OppNetConsole} running on the local host,
 * and the panel allows to enter commands that are sent to the console and
 * display its replies.
 * 
 */
public class ConsolePanel extends JPanel implements Closeable, KeyListener {

    private static final String PROMPT = "> ";
    private static final int PROMPT_LENGTH = PROMPT.length();
    private final JTextArea textArea;
    private final Socket socket;
    private final InputStream in;
    private final PrintWriter out;
    private final List<String> history;
    private int hIdx;

    //---------------------------------------------------------------
    public ConsolePanel(int port) throws IOException {
        history = new LinkedList<>();

        textArea = makeTextArea();
        JScrollPane scrollPane = new JScrollPane(textArea);
        add(scrollPane);

        socket = new Socket("localhost", port);
        in = new ConsoleInputStream(socket.getInputStream());
        out = new PrintWriter(socket.getOutputStream(), true);
        startReading(socket, in);
    }

    //---------------------------------------------------------------
    private void startReading(final Socket socket, final InputStream in) {
        new Thread() {
            @Override
            public void run() {
                while (!socket.isClosed()) {
                    try {
                        in.read();
                    } catch (IOException ex) {
                        // DO NOTHING
                    }
                }
            }
        }.start();
    }

    //---------------------------------------------------------------
    @Override
    public void close() {
        out.close();
        try {
            in.close();
        } catch (IOException ex) {
            // DO NOTHING
        }
        try {
            socket.close();
        } catch (IOException ex) {
            // DO NOTHING
        }
    }

    //---------------------------------------------------------------
    @Override
    public void keyPressed(KeyEvent ke) {
        try {
            int line = textArea.getLineCount() - 1;
            int start = textArea.getLineStartOffset(line) + PROMPT_LENGTH;
            int end = textArea.getLineEndOffset(line);
            int caret = textArea.getCaretPosition();
            if (caret < start || caret > end) {
                ke.consume();
                return;
            }
            String text;
            int code = ke.getKeyCode();
            switch (code) {
                case KeyEvent.VK_ENTER:
                    ke.consume();
                    text = textArea.getText(start, end - start);
                    history.add(text);
                    hIdx = history.size();
                    out.println(text);
                    textArea.append("\n");
                    break;
                case KeyEvent.VK_DELETE:
                case KeyEvent.VK_BACK_SPACE:
                    if (caret == start) {
                        ke.consume();
                    }
                    break;
                case KeyEvent.VK_UP: // prev command in history
                    ke.consume();
                    if (hIdx > 0) {
                        hIdx--;
                        textArea.replaceRange(history.get(hIdx), start, end);
                    }
                    break;
                case KeyEvent.VK_DOWN: // next command in history 
                    ke.consume();
                    if (hIdx < history.size()) {
                        hIdx++;
                        text = (hIdx < history.size() ? history.get(hIdx) : "");
                        textArea.replaceRange(text, start, end);
                    }
                    break;
                case KeyEvent.VK_L: // clear screen
                    if (ke.isControlDown()) {
                        ke.consume();
                        textArea.setText("");
                    }
                default:
                    break;
            }
        } catch (BadLocationException ex) {
            // DO NOTHING
        }
    }

    @Override
    public void keyTyped(KeyEvent ke) {
        // DO NOTHING
    }

    @Override
    public void keyReleased(KeyEvent ke) {
        // DO NOTHING
    }

    //---------------------------------------------------------------
    class ConsoleInputStream extends InputStream {

        private InputStream in;
        private String prevText = "";

        public ConsoleInputStream(InputStream in) {
            this.in = in;
            textArea.append(PROMPT);
            textArea.setCaretPosition(PROMPT_LENGTH);
        }

        @Override
        public int read() throws IOException {
            int i = in.read();
            String text = String.valueOf((char) i);
            textArea.append(text);
            if (text.equals("\n") && prevText.endsWith(".")) {
                textArea.append(PROMPT);
            }
            prevText = text;
            textArea.setCaretPosition(textArea.getDocument().getLength());
            return i;
        }
    }

    //---------------------------------------------------------------
    private JTextArea makeTextArea() {
        JTextArea textArea = new JTextArea(30, 80);
        textArea.addKeyListener(this);
        textArea.setBackground(Color.black);
        textArea.setFont(new Font("monospaced", Font.PLAIN, 12));
        textArea.setForeground(Color.white);
        textArea.setCaretColor(Color.white);
        return textArea;
    }

    //---------------------------------------------------------------
    public static void main(String[] args) throws IOException {
        JFrame frame = new JFrame();
        frame.setSize(800, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(new ConsolePanel(Integer.parseInt(args[0])));
        frame.setVisible(true);
    }
}
