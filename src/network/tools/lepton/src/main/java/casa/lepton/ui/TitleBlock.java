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

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.font.FontRenderContext;
import java.awt.font.GlyphVector;

/**
 *
 * Fixed-size rectangular area containing a text, that can be inserted in a
 * graphics2d. The updating of the text and its drawing is intended to be fast
 * (method draw) The characteristics of the rectangle and text (position, size,
 * font, colors) are defined at creation time. The size of the rectangle is
 * defined from a provided text sample.
 *
 */
public class TitleBlock {

    Graphics2D g2d = null;

    private Font font;
    private Color fgColor, bgColor;

    // position of the text
    private int textX, textY;
    // position and size of the rectangle 
    int rectX, rectY, rectWidth, rectHeight;

    public TitleBlock(Graphics2D g, Rectangle target, Corner corner, String textSample, Font f, Color fg, Color bg) {

        this.g2d = g;

        this.fgColor = fg;
        this.bgColor = bg;

        this.font = f;

        int padding = (int) (font.getSize() * 0.5);

        FontRenderContext frc = g.getFontRenderContext();
        GlyphVector gv = f.createGlyphVector(frc, textSample);

        Rectangle textRect = gv.getPixelBounds(null, 0, 0);

        int textWidth = (int) Math.ceil(textRect.getWidth());
        int textHeight = (int) Math.ceil(textRect.getHeight());

        int internalPadding = (int) (textHeight * 0.25);

        rectWidth = textWidth + 2 * internalPadding;
        rectHeight = textHeight + 2 * internalPadding;

        switch (corner) {
            case NORTH_WEST:
                rectX = target.x + padding;
                rectY = target.y + padding;
                break;
            case NORTH_EAST:
                rectX = target.x + target.width - rectWidth - padding;
                rectY = target.y + padding;
                break;
            case SOUTH_WEST:
                rectX = target.x + padding;
                rectY = target.y + target.height - rectHeight - padding;
                break;
            case SOUTH_EAST:
            default:
                rectX = target.x + target.width - rectWidth - padding;
                rectY = target.y + target.height - rectHeight - padding;
                break;
        }

        textX = rectX + internalPadding;
        textY = rectY + textHeight + internalPadding;

    }

    public void draw(String text) {

        Color savedColor = this.g2d.getColor();
        Font savedFont = this.g2d.getFont();

        this.g2d.setFont(this.font);

        if (this.bgColor != null) {
            this.g2d.setColor(this.bgColor);
            g2d.fillRect(rectX, rectY, rectWidth, rectHeight);
        }

        this.g2d.setColor(this.fgColor);
        g2d.drawString(text, textX, textY);

        this.g2d.setColor(savedColor);
        this.g2d.setFont(savedFont);
    }

}
