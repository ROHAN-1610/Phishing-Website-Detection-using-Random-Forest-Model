import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Create figure and axes
fig, ax = plt.subplots(figsize=(12, 18))

# Hide axes
ax.axis('off')

# Define colors
box_color = 'lightblue'
arrow_color = 'black'

# Define positions and sizes
box_width = 0.6
box_height = 0.1
start_x = 0.5
start_y = 0.95
vertical_gap = 0.03

# Define the labels for each box
labels = [
    "User\n(Interacts with Web App)",
    "Web Browser\n(HTML/CSS/JavaScript)",
    "Voice Commands\n(voiceCommands.js)",
    "Start/Stop\nVoice Commands",
    "Send Audio Data\nto Flask Server",
    "Flask Server (API Endpoint)\n/speech-to-text",
    "Google Cloud\nSpeech API",
    "Receive Transcript",
    "Return Transcript\nto Flask Server",
    "Send Transcript\nto Client",
    "Handle Voice Command\n(voiceCommands.js)",
    "Execute Command (Map)\n(app.js)",
    "Update Map Interface",
    "Update Command List"
]

# Define positions for the boxes
positions = [(start_x, start_y - i * (box_height + vertical_gap)) for i in range(len(labels))]

# Draw the boxes with text
for (x, y), label in zip(positions, labels):
    rect = patches.FancyBboxPatch(
        (x - box_width / 2, y - box_height / 2),
        box_width,
        box_height,
        boxstyle="round,pad=0.1",
        edgecolor=arrow_color,
        facecolor=box_color,
        linewidth=1.5
    )
    ax.add_patch(rect)
    ax.text(
        x,
        y,
        label,
        ha='center',
        va='center',
        fontsize=10,
        wrap=True
    )

# Draw the arrows
for (x1, y1), (x2, y2) in zip(positions[:-1], positions[1:]):
    ax.annotate(
        '',
        xy=(x2, y2 + box_height / 2),
        xytext=(x1, y1 - box_height / 2),
        arrowprops=dict(facecolor=arrow_color, edgecolor=arrow_color, arrowstyle='->')
    )

plt.show()
