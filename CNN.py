import matplotlib.pyplot as plt
import torch
from torchvision import datasets, transforms
from torch.utils.data import DataLoader

transform = transforms.Compose([
    transforms.ToTensor()
])

train_dataset = datasets.MNIST(root='./data_stl', train=True, download=True, transform=transform)
val_dataset = datasets.MNIST(root='./data_stl', train=False, download=True, transform=transform)

BATCH_SIZE = 16

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

import torch.nn as nn

class SimpleCNN(nn.Module):
    def __init__(self):
      super().__init__()
      self.sequential = nn.Sequential(
          nn.Conv2d(in_channels = 1, out_channels = 32, kernel_size = 3, stride = 1, padding = 'same'),
          nn.ReLU(),
          nn.MaxPool2d(kernel_size = 2, stride = 2),

          nn.Conv2d(in_channels = 32, out_channels = 64, kernel_size = 3, stride = 1, padding = 'same'),
          nn.ReLU(),
          nn.MaxPool2d(kernel_size = 2, stride = 2),

          nn.Flatten(),
          nn.Linear(64 * 7 * 7, 10)
      )

    def forward(self, x):
      return self.sequential(x)

model_mnist = SimpleCNN().to(device)

from tqdm.notebook import tqdm

def accuracy_fn(y_true,y_pred):
  correct = torch.eq(y_true,y_pred).sum().item()
  acc = (correct/len(y_pred))*100
  return acc

def train(model, train_loader, loss_fn, optimizer):
    model.train()
    total_loss = 0
    total_acc = 0
    num_batches = 0
    for images, target in tqdm(train_loader, desc = 'Training'):
      images = images.to(device)
      target = target.to(device)

      optimizer.zero_grad()

      outputs = model(images)

      loss = loss_fn(outputs, target)
      loss.backward()
      optimizer.step()
      total_loss += loss.item()

      _, predicted = torch.max(outputs, dim=1)
      acc = accuracy_fn(target, predicted)
      total_acc += acc

      num_batches += 1

      avg_loss = total_loss / num_batches
      avg_acc = total_acc / num_batches

    return avg_loss, avg_acc


def validate(model, val_loader, loss_fn):
    model.eval()
    total_loss = 0
    total_acc = 0
    num_batches = 0
    with torch.no_grad():
      for images, target in tqdm(val_loader, desc = 'Validation'):
        images = images.to(device)
        target = target.to(device)

        outputs = model(images)

        loss = loss_fn(outputs, target)
        total_loss += loss.item()

        _, predicted = torch.max(outputs, dim=1)
        acc = accuracy_fn(target, predicted)
        total_acc += acc

        num_batches += 1

        avg_loss = total_loss / num_batches
        avg_acc = total_acc / num_batches

    return avg_loss, avg_acc

loss_fn = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model_mnist.parameters(), lr=0.0001)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5, verbose=True)

EPOCHS = 5
best_val_loss = float('inf')

for epoch in range(EPOCHS):
    train_loss, train_acc = train(model_mnist, train_loader, loss_fn, optimizer)
    val_loss, val_acc = validate(model_mnist, val_loader, loss_fn)

    print(f"Epoch: {epoch+1}, Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}", end = ' ')
    print(f"Train Acc: {train_acc:.2f}%, Val Acc: {val_acc:.2f}%")

    if val_loss < best_val_loss:
      best_val_loss = val_loss
      torch.save(model_mnist.state_dict(), 'best_model_mnist.pth')
      print("Saved best model")

    scheduler.step(val_loss)

import matplotlib.pyplot as plt

def plot_predictions(model, dataloader, device, num_images=4):
    model.eval()
    images_shown = 0

    plt.figure(figsize=(10, 5))

    with torch.no_grad():
        for images, labels in dataloader:
            images = images.to(device)
            outputs = model(images)
            _, preds = torch.max(outputs, 1)

            for i in range(images.size(0)):
                if images_shown >= num_images:
                    break

                image = images[i].cpu().squeeze()
                pred = preds[i].item()

                plt.subplot(1, num_images, images_shown + 1)
                plt.imshow(image, cmap='gray')
                plt.title(f"Predicted: {pred}")
                plt.axis('off')

                images_shown += 1
            if images_shown >= num_images:
                break

    plt.tight_layout()
    plt.show()

plot_predictions(model_mnist, val_loader, device,3)