#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>

const char *file_dev = "/dev/memdev";
const char *file_rule = "rule.txt";
static gchar *titles[7] = {"【源地址】","【源端口】","【协议】","【目的地址】","【目的端口】","【时间】","【动作】"};
gchar *new_row[7];
GtkWidget *clist;
gint row_count = 0;
gint select_row = 0;
gboolean select_flag = FALSE;
GtkWidget *add_win;
GtkWidget *entry_saddr;
GtkWidget *entry_smask;
GtkWidget *entry_sport;
GtkWidget *entry_daddr;
GtkWidget *entry_dmask;
GtkWidget *entry_dport;
GtkWidget *entry_ltime;
GtkWidget *entry_rtime;
GtkWidget *combo1, *combo2, *combo3;  
gchar protocol[10] = "ANY";
gchar tvalid[10] = "invalid";
gchar action[10] = "Reject";

struct list{
    char data[100];
    struct list *next;
};

void show_list_from_file(const char *filename);
void on_quit_clicked(GtkWidget *widget, gpointer window);
void on_modify_clicked(GtkWidget *widget, gpointer window);
void on_del_clicked(GtkWidget *widget, gpointer window);
void on_clear_clicked(GtkWidget *widget, gpointer window);
void on_add_clicked(GtkWidget *widget, gpointer data);
void selection_made( GtkWidget *clist, gint row, gint column, GdkEventButton *event, gpointer data);
void on_ok_clicked(GtkButton *button, gpointer data);
void on_cancel_clicked(GtkButton *button, gpointer data);
GtkWidget* create_addwin(void);
void combo1_selected(GtkWidget *widget, gpointer data);
void combo2_selected(GtkWidget *widget, gpointer data);
void combo3_selected(GtkWidget *widget, gpointer data);

int main(int argc, char *argv[])
{
    GtkWidget *window;
    GdkPixbuf *pixbuf;
    PangoFontDescription *font;
    GtkWidget *hbox;
    GtkWidget *vbox;
    GtkWidget *scrolled;
    GtkWidget *button_add;
    GtkWidget *button_del;
    GtkWidget *button_modify;
    GtkWidget *button_clear;
    GtkWidget *button_quit;

    gtk_init(&argc,&argv);    //初始化
//主窗口创建
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window),"轻量级小型网络防火墙");
    g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_window_set_position(GTK_WINDOW(window),GTK_WIN_POS_CENTER);
    gtk_window_set_default_size(GTK_WINDOW(window),1200,500);
    gtk_container_set_border_width(GTK_CONTAINER(window),10);
    pixbuf = gdk_pixbuf_new_from_file("1.jpg", NULL);
    gtk_window_set_icon(GTK_WINDOW(window),pixbuf);
//字体设置
    font = pango_font_description_from_string("Sans");
    pango_font_description_set_size(font, 20 * PANGO_SCALE);
//主体界面
    hbox = gtk_hbox_new(FALSE,0);
    gtk_container_add(GTK_CONTAINER(window), hbox);

    scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),GTK_POLICY_AUTOMATIC,GTK_POLICY_ALWAYS);
    gtk_box_pack_start(GTK_BOX(hbox), scrolled, TRUE, TRUE, 5);

    clist = gtk_clist_new_with_titles(7, titles);
    gtk_signal_connect(GTK_OBJECT(clist), "select_row", GTK_SIGNAL_FUNC(selection_made),NULL);

    gtk_clist_set_shadow_type(GTK_CLIST(clist), GTK_SHADOW_OUT);
    gtk_clist_set_row_height(GTK_CLIST(clist), 30);
    gtk_clist_set_column_width(GTK_CLIST(clist), 0, 200);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_width(GTK_CLIST(clist), 1, 100);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_width(GTK_CLIST(clist), 2, 100);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_width(GTK_CLIST(clist), 3, 200);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_width(GTK_CLIST(clist), 4, 100);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_width(GTK_CLIST(clist), 5, 250);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_CENTER);
    gtk_clist_set_column_width(GTK_CLIST(clist), 6, 50);
    gtk_clist_set_column_justification(GTK_CLIST(clist), 6, GTK_JUSTIFY_CENTER);

    gtk_clist_thaw(GTK_CLIST(clist));

    gtk_container_add(GTK_CONTAINER(scrolled), clist);

    vbox = gtk_vbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 5);

    button_add = gtk_button_new_with_label("Add");
    gtk_box_pack_start(GTK_BOX(vbox), button_add, FALSE, FALSE, 3);
    g_signal_connect(G_OBJECT(button_add), "clicked", G_CALLBACK(on_add_clicked), NULL);

    button_del = gtk_button_new_with_label("Del");
    gtk_box_pack_start(GTK_BOX(vbox), button_del, FALSE, FALSE, 3);
    g_signal_connect(G_OBJECT(button_del), "clicked", G_CALLBACK(on_del_clicked), (gpointer)window);

    button_modify = gtk_button_new_with_label("Modify");
    gtk_box_pack_start(GTK_BOX(vbox), button_modify, FALSE, FALSE, 3);
    g_signal_connect(G_OBJECT(button_modify), "clicked", G_CALLBACK(on_modify_clicked), (gpointer)window);

    button_clear = gtk_button_new_with_label("Clear");
    gtk_box_pack_start(GTK_BOX(vbox), button_clear, FALSE, FALSE, 3);
    g_signal_connect(G_OBJECT(button_clear), "clicked", G_CALLBACK(on_clear_clicked), (gpointer)window);

    button_quit = gtk_button_new_with_label("Quit");
    gtk_box_pack_start(GTK_BOX(vbox), button_quit, FALSE, FALSE, 3);
    g_signal_connect(G_OBJECT(button_quit), "clicked", G_CALLBACK(on_quit_clicked), (gpointer)window);
//具体操作
    show_list_from_file(file_rule);

//显示窗口，以及程序循环
    gtk_widget_show(window);
    gtk_widget_show_all(window);
    gtk_main();
    return 0;
}

void show_list_from_file(const char *filename)
{
    FILE *fp1 = NULL, *fp0 = NULL;
    gchar buf[100];
    gint num, i;
    gchar saddr[32], daddr[32];
    gint sport, dport, smask, dmask, protocol, valid, action;
    gint lhour, lmin, lsec, rhour, rmin, rsec;
    gchar string[7][32];
    if((fp1 = fopen(filename,"r+")) == NULL){
        printf("open \"%s\" error!\n",filename);
        return;
    }
    fgets(buf, 100, fp1);
    sscanf(buf, "%d", &num);
    for(i = 0; i < num; i++){
        fgets(buf, 100, fp1);
        sscanf(buf, "%s /%d:%d, %s /%d:%d, %d, %d, %d:%d:%d, %d:%d:%d, %d",
                          saddr, &smask, &sport,
                          daddr, &dmask, &dport,
                          &protocol,
                          &valid,
                          &lhour, &lmin, &lsec,
                          &rhour, &rmin, &rsec,
                          &action);
        sprintf(string[0], "%s /%d",saddr, smask);
        new_row[0] = string[0];
        sprintf(string[1], "%d",sport);
        new_row[1] = string[1];
        switch(protocol){
            case 255: 
                strcpy(string[2], "ANY"); break;
            case 1:
                strcpy(string[2], "ICMP");break;
            case 6:
                strcpy(string[2], "TCP"); break;
            case 17:
                strcpy(string[2], "UDP"); break;
            default:
                strcpy(string[2], "unknow");
        }
        new_row[2] = string[2];
        sprintf(string[3], "%s /%d",daddr, dmask);
        new_row[3] = string[3];
        sprintf(string[4], "%d",dport);
        new_row[4] = string[4];
        if(valid == 1)
            sprintf(string[5], "%02d:%02d:%02d-%02d:%02d:%02d / valid", lhour, lmin, lsec, rhour, rmin, rsec);
        else if(valid == 0)
            sprintf(string[5], "%02d:%02d:%02d-%02d:%02d:%02d / invalid", lhour, lmin, lsec, rhour, rmin, rsec);
        new_row[5] = string[5];
        if(action == 1)
            strcpy(string[6], "Permit");
        else if(action == 0)
            strcpy(string[6], "Reject");
        new_row[6] = string[6]; 
        gtk_clist_append(GTK_CLIST(clist), new_row);
        row_count++;
    }
    fclose(fp1);
    
    if((fp0 = fopen(file_dev,"a+")) == NULL)
    {
       printf("open memdev error!\n");
       return;
    }
    if((fp1 = fopen(file_rule,"r+")) == NULL){
        printf("open rule.txt error!\n");
        return;
    }

    fgets(buf, 100, fp1);
    sscanf(buf, "%d", &num);
    printf("【user_data】\n<row 1>: %d\n", num);
    fprintf(fp0, "%s", buf);
    for(i = 0; i < num; i++){
        fgets(buf, 100, fp1);
        printf("<row %d>: %s", i+2, buf);
        fprintf(fp0, "%s", buf);
    }
    fclose(fp1);
    //检验是否写入内核正确
    printf("\n【kernel_data】\n");
    fseek(fp0, 0, SEEK_SET);
    for(i = 0; i <= num; i++){
        fgets(buf, 100, fp0);
        printf("<row %d>: %s", i+1, buf);
    }
    printf("\n\n");
    fclose(fp0);
}

GtkWidget* create_addwin(void){
    GtkWidget *win;
    GtkWidget *table;
    GtkWidget *bbox;
    GtkWidget *vbox;
    GtkWidget* label;
    GtkWidget* button;

    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win),"Add rule");
    gtk_window_set_position(GTK_WINDOW(win),GTK_WIN_POS_CENTER);
    g_signal_connect(G_OBJECT(win),"delete_event",G_CALLBACK(gtk_widget_destroy),win);
    gtk_container_set_border_width(GTK_CONTAINER(win),10);

    vbox = gtk_vbox_new(FALSE,0);
    gtk_container_add(GTK_CONTAINER(win),vbox);
    table = gtk_table_new(11,2,FALSE);
    gtk_box_pack_start(GTK_BOX(vbox),table,FALSE,FALSE,5);

    label = gtk_label_new("源地址     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,0,1);
    entry_saddr = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_saddr,1,2,0,1);

    label = gtk_label_new("源掩码     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,1,2);
    entry_smask = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_smask,1,2,1,2);

    label = gtk_label_new("源端口     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,2,3);
    entry_sport = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_sport,1,2,2,3);

    label = gtk_label_new("协议     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,3,4);
    combo1 = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo1),"ANY");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo1),"TCP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo1),"UDP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo1),"ICMP");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo1), 0);
    gtk_table_attach_defaults(GTK_TABLE(table),combo1,1,2,3,4);
    g_signal_connect(G_OBJECT(combo1), "changed", G_CALLBACK(combo1_selected), NULL);

    label = gtk_label_new("目的地址     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,4,5);
    entry_daddr = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_daddr,1,2,4,5);

    label = gtk_label_new("目的掩码     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,5,6);
    entry_dmask = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_dmask,1,2,5,6);

    label = gtk_label_new("目的端口     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,6,7);
    entry_dport = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_dport,1,2,6,7);

    label = gtk_label_new("时间控制     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,7,8);
    combo2 = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo2),"invalid");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo2),"valid");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo2), 0);
    gtk_table_attach_defaults(GTK_TABLE(table),combo2,1,2,7,8);
    g_signal_connect(G_OBJECT(combo2), "changed", G_CALLBACK(combo2_selected), NULL); 

    label = gtk_label_new("起始时间     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,8,9);
    entry_ltime = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_ltime,1,2,8,9);

    label = gtk_label_new("终止时间     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,9,10);
    entry_rtime = gtk_entry_new();
    gtk_table_attach_defaults(GTK_TABLE(table),entry_rtime,1,2,9,10);

    label = gtk_label_new("动作     ");
    gtk_table_attach_defaults(GTK_TABLE(table),label,0,1,10,11);
    combo3 = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo3),"Reject");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo3),"Permit");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo3), 0); 
    gtk_table_attach_defaults(GTK_TABLE(table),combo3,1,2,10,11); 
    g_signal_connect(G_OBJECT(combo3), "changed", G_CALLBACK(combo3_selected), NULL);

    bbox = gtk_hbutton_box_new();
    gtk_box_pack_start(GTK_BOX(vbox),bbox,FALSE,FALSE,5);
    gtk_box_set_spacing(GTK_BOX(bbox),5);

    gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox),GTK_BUTTONBOX_END);
    button = gtk_button_new_from_stock(GTK_STOCK_OK);
    g_signal_connect(G_OBJECT(button),"clicked",G_CALLBACK(on_ok_clicked),NULL);
    gtk_box_pack_start(GTK_BOX(bbox),button,FALSE,FALSE,5);

    button = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
    g_signal_connect(G_OBJECT(button),"clicked",G_CALLBACK(on_cancel_clicked),NULL);
    gtk_box_pack_start(GTK_BOX(bbox),button,FALSE,FALSE,5);

    gtk_widget_show_all(win);

    return win;
}

void on_quit_clicked(GtkWidget *widget, gpointer window)
{
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new((GtkWindow *)window,
                                  GTK_DIALOG_DESTROY_WITH_PARENT,
                                  GTK_MESSAGE_QUESTION,
                                  GTK_BUTTONS_OK_CANCEL,
                                  "Are you sure to quit?"
                                  );
  gtk_window_set_position(GTK_WINDOW(dialog),GTK_WIN_POS_CENTER);
  gtk_window_set_title(GTK_WINDOW(dialog), "Question");
  if(gtk_dialog_run(GTK_DIALOG(dialog)) == -5)
  {
      gtk_main_quit();
  }
  gtk_widget_destroy(dialog);
}

void on_modify_clicked(GtkWidget *widget, gpointer window)
{
    GtkWidget *dialog;
    dialog = gtk_message_dialog_new((GtkWindow *)window,
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_MESSAGE_INFO,
                                    GTK_BUTTONS_OK,
                                    "This function not realize yet!"
                                   );
    gtk_window_set_position(GTK_WINDOW(dialog),GTK_WIN_POS_CENTER);
    gtk_window_set_title(GTK_WINDOW(dialog), "Warnning");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

void on_clear_clicked(GtkWidget *widget, gpointer window)
{
    GtkWidget *dialog;
    dialog = gtk_message_dialog_new((GtkWindow *)window,
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_MESSAGE_QUESTION,
                                    GTK_BUTTONS_OK_CANCEL,
                                    "Are you sure to clear the whole list?"
                                   );
    gtk_window_set_position(GTK_WINDOW(dialog),GTK_WIN_POS_CENTER);
    gtk_window_set_title(GTK_WINDOW(dialog), "Question");
    if(row_count > 0 && gtk_dialog_run(GTK_DIALOG(dialog)) == -5)
    {
        FILE *fp1 = NULL, *fp0 = NULL;
        char buf[100];
        int num, i;
        gtk_clist_clear(GTK_CLIST(clist));
        row_count = 0;
        if((fp1 = fopen(file_rule,"w+")) == NULL){
            printf("open \"%s\" error!\n",file_rule);
            return;
        }
        fclose(fp1);

        if((fp0 = fopen(file_dev,"a+")) == NULL)
        {
           printf("open \"%s\" error!\n", file_dev);
           return;
        }
        if((fp1 = fopen(file_rule,"r+")) == NULL){
            printf("open \"%s\" error!\n", file_rule);
            return;
        }

        fgets(buf, 100, fp1);
        sscanf(buf, "%d", &num);
        printf("【user_data】\n<row 1>: %d\n", num);
        fprintf(fp0, "%s", buf);
        for(i = 0; i < num; i++){
            fgets(buf, 100, fp1);
            printf("<row %d>: %s", i+2, buf);
            fprintf(fp0, "%s", buf);
        }
        fclose(fp1);
        printf("\n【kernel_data】\n");
        fseek(fp0, 0, SEEK_SET);
        for(i = 0; i <= num; i++){
            fgets(buf, 80, fp0);
            printf("<row %d>: %s", i+1, buf);
        }
        printf("\n\n");
        fclose(fp0);
    }
    gtk_widget_destroy(dialog);
}

void on_del_clicked(GtkWidget *widget, gpointer window)
{
    GtkWidget *dialog1, *dialog2;
    FILE *fp0 = NULL;
    FILE *fp1 = NULL;
    int num, i;
    char buf[100];
    dialog1 = gtk_message_dialog_new((GtkWindow *)window,
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_MESSAGE_QUESTION,
                                    GTK_BUTTONS_OK_CANCEL,
                                    "Are you sure to delete the regulation?"
                                   );
    dialog2 = gtk_message_dialog_new((GtkWindow *)window,
                                    GTK_DIALOG_DESTROY_WITH_PARENT,
                                    GTK_MESSAGE_INFO,
                                    GTK_BUTTONS_OK,
                                    "Please select a row!"
                                   );
    gtk_window_set_position(GTK_WINDOW(dialog1),GTK_WIN_POS_CENTER);
    gtk_window_set_title(GTK_WINDOW(dialog1), "Question");
    gtk_window_set_position(GTK_WINDOW(dialog2),GTK_WIN_POS_CENTER);
    gtk_window_set_title(GTK_WINDOW(dialog2), "Warnning");
    if(select_flag && row_count > 0){
        if(gtk_dialog_run(GTK_DIALOG(dialog1)) == -5){
            gtk_clist_remove(GTK_CLIST(clist), select_row);
            --row_count;
            if((fp1 = fopen(file_rule,"r+")) == NULL){
                printf("open \"%s\" error!\n",file_rule);
                return;
            }
            struct list *head = NULL;
            struct list *pre, *p;
            head = (struct list *)malloc(sizeof(struct list));
            head -> next = NULL;
            pre = head;
            p = head;
            fgets(buf, 100, fp1);
            sscanf(buf, "%d", &num);
            for(i = 0; i < num; i++){
                fgets(buf, 100, fp1);
                if(i == select_row){
                    continue;
                }
                p = (struct list *)malloc(sizeof(struct list));
                strcpy(p->data, buf);
                pre -> next = p;
                pre = p;
            }
            p->next = NULL;
            fclose(fp1);

            if((fp1 = fopen(file_rule,"w+")) == NULL){
                printf("open \"%s\" error!\n",file_rule);
                return;
            }
            --num;
            if(num > 0)
                fprintf(fp1, "%d\n", num);
            pre = head;
            p = head -> next;
            free(pre);
            while(p != NULL){
                fprintf(fp1, "%s", p->data);
                pre = p;
                p = p->next;
                free(pre);
            }
            fclose(fp1);

            if((fp0 = fopen(file_dev,"a+")) == NULL)
            {
               printf("open memdev error!\n");
               return;
            }
            if((fp1 = fopen(file_rule,"r+")) == NULL){
                printf("open rule.txt error!\n");
                return;
            }

            fgets(buf, 100, fp1);
            sscanf(buf, "%d", &num);
            printf("【user_data】\n<row 1>: %d\n", num);
            fprintf(fp0, "%s", buf);
            for(i = 0; i < num; i++){
                fgets(buf, 100, fp1);
                printf("<row %d>: %s", i+2, buf);
                fprintf(fp0, "%s", buf);
            }
            fclose(fp1);
            /*
            printf("\n【kernel_data】\n");
            fseek(fp0, 0, SEEK_SET);
            for(i = 0; i <= num; i++){
                fgets(buf, 80, fp0);
                printf("<row %d>: %s", i+1, buf);
            }
            printf("\n\n");
            */
            fclose(fp0);
        }
        gtk_widget_destroy(dialog1);
    }
    else{
        gtk_dialog_run(GTK_DIALOG(dialog2));
        gtk_widget_destroy(dialog2);
    }
}

void on_add_clicked(GtkWidget *widget, gpointer data)
{
    add_win = create_addwin();
    gtk_widget_show(add_win);
}

void on_ok_clicked(GtkButton *button, gpointer data)
{
    gchar string[7][32];
    char buf[100];
    gchar const *temp1 = NULL;
    gchar const *temp2 = NULL;
    FILE *fp0 = NULL;
    FILE *fp1 = NULL;
    int num, i;
    gchar *text;

    if((fp1 = fopen(file_rule,"r+")) == NULL){
        printf("open \"%s\" error!\n",file_rule);
       return;
    }
    struct list *head = NULL;
    struct list *pre, *p;
    head = (struct list *)malloc(sizeof(struct list));
    head -> next = NULL;
    pre = head;
    p = head;
    fgets(buf, 100, fp1);
    num = row_count;
    //printf("%d\n",num);
    for(i = 0; i < num; i++){
        fgets(buf, 100, fp1);
        p = (struct list *)malloc(sizeof(struct list));
        strcpy(p->data, buf);
        pre -> next = p;
        pre = p;
    }
    p->next = NULL;
    fclose(fp1);

    if((fp1 = fopen(file_rule,"w+")) == NULL){
        printf("open \"%s\" error!\n",file_rule);
        return;
    }
    ++num;
    if(num < 1){
        fclose(fp1);
        return;
    }
    fprintf(fp1, "%d\n", num);
    pre = head;
    p = head -> next;
    free(pre);
    while(p != NULL){
        fprintf(fp1, "%s", p->data);
        pre = p;
        p = p->next;
        free(pre);
    }

    temp1 = gtk_entry_get_text(GTK_ENTRY(entry_saddr));
    temp2 = gtk_entry_get_text(GTK_ENTRY(entry_smask));
    if(strcmp(temp1, "") == 0){
        if(strcmp(temp2, "") == 0)
            strcpy(string[0], "0.0.0.0 /32");
        else
            sprintf(string[0],"0.0.0.0 /%s", temp2);
    }
    else{
        if(strcmp(temp2, "") == 0)
            sprintf(string[0],"%s /32", temp1);
        else
            sprintf(string[0],"%s /%s", temp1, temp2);
    }
    if(num == 1)
        fprintf(fp1, "%s", string[0]);
    else
        fprintf(fp1, "\n%s", string[0]);
    new_row[0] = string[0];

    temp1 = gtk_entry_get_text(GTK_ENTRY(entry_sport));
    if(strcmp(temp1, "") == 0)
        strcpy(string[1], "65535");
    else
        sprintf(string[1], "%s", temp1);
    fprintf(fp1, ":%s, ", string[1]);
    new_row[1] = string[1];

    text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(combo1));
    strcpy(protocol, text);
    free(text);

    if(protocol == NULL)
        strcpy(string[2], "ANY");
    else
        strcpy(string[2],protocol);
    new_row[2] = string[2];
    //printf("protocol:%s, len = %d\n", protocol, (int)strlen(protocol));

    temp1 = gtk_entry_get_text(GTK_ENTRY(entry_daddr));
    temp2 = gtk_entry_get_text(GTK_ENTRY(entry_dmask));
    if(strcmp(temp1, "") == 0){
        if(strcmp(temp2, "") == 0)
            strcpy(string[3], "0.0.0.0 /32");
        else
            sprintf(string[3],"0.0.0.0 /%s", temp2);
    }
    else{
        if(strcmp(temp2, "") == 0)
            sprintf(string[3],"%s /32", temp1);
        else
            sprintf(string[3],"%s /%s", temp1, temp2);
    }
    fprintf(fp1, "%s", string[3]);
    new_row[3] = string[3];

    temp1 = gtk_entry_get_text(GTK_ENTRY(entry_dport));
    if(strcmp(temp1, "") == 0)
        strcpy(string[4], "65535");
    else
        sprintf(string[4], "%s", temp1);
    fprintf(fp1, ":%s, ", string[4]);
    new_row[4] = string[4];

    if(strcmp(protocol, "TCP") == 0)
        fprintf(fp1, "%s, ", "6");
    else if(strcmp(protocol, "UDP") == 0)
        fprintf(fp1, "%s, ", "17");
    else if(strcmp(protocol, "ICMP") == 0)
        fprintf(fp1, "%s, ", "1");
    else
        fprintf(fp1, "%s, ", "255");

    if(strcmp(tvalid, "invalid") == 0)
        fprintf(fp1, "%s, ", "0");
    else
        fprintf(fp1, "%s, ", "1");

    text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(combo2));
    strcpy(tvalid, text);
    free(text);

    temp1 = gtk_entry_get_text(GTK_ENTRY(entry_ltime));
    temp2 = gtk_entry_get_text(GTK_ENTRY(entry_rtime));

    if(strcmp(temp1, "") == 0){
        if(strcmp(temp2, "") == 0){
            if(tvalid == NULL)
                sprintf(string[5], "00:00:00-24:00:00 / invalid");
            else
                sprintf(string[5], "00:00:00-24:00:00 / %s", tvalid);
            fprintf(fp1, "%s, %s, ", "00:00:00", "24:00:00");
        }
        else{
            if(tvalid == NULL)
                sprintf(string[5],"00:00:00-%s / invalid", temp2);
            else
                sprintf(string[5],"00:00:00-%s / %s", temp2, tvalid);
            fprintf(fp1, "%s, %s, ", "00:00:00", temp2);
        } 
    }
    else{
        if(strcmp(temp2, "") == 0){
            if(tvalid == NULL)
                sprintf(string[5], "%s-24:00:00 / invalid", temp1);
            else
                sprintf(string[5], "%s-24:00:00 / %s", temp1, tvalid);
            fprintf(fp1, "%s, %s, ", temp1, "24:00:00");
        }
        else{
            if(tvalid == NULL)
                sprintf(string[5],"%s-%s / invalid", temp1, temp2);
            else
                sprintf(string[5],"%s-%s / %s", temp1, temp2, tvalid);
            fprintf(fp1, "%s, %s, ", temp1, temp2);
        }
            
    }
    new_row[5] = string[5];

    text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(combo3));
    strcpy(action, text);
    free(text);

    if(action == NULL)
        strcpy(string[6], "Reject");
    else
        strcpy(string[6], action);

    if(strcmp(action, "Reject") == 0)
        fprintf(fp1, "%s", "0");
    else
        fprintf(fp1, "%s", "1");

    new_row[6] = string[6]; 
    row_count++;
    gtk_clist_append(GTK_CLIST(clist), new_row);
    fclose(fp1);

    if((fp0 = fopen(file_dev,"a+")) == NULL)
    {
       printf("open memdev error!\n");
       return;
    }
    if((fp1 = fopen(file_rule,"r+")) == NULL){
        printf("open rule.txt error!\n");
        return;
    }

    fgets(buf, 100, fp1);
    sscanf(buf, "%d", &num);
    printf("【user_data】\n<row 1>: %d\n", num);
    fprintf(fp0, "%s", buf);
    for(i = 0; i < num; i++){
        fgets(buf, 100, fp1);
        printf("<row %d>: %s", i+2, buf);
        fprintf(fp0, "%s", buf);
    }
    fclose(fp1);
    /*
    printf("\n【kernel_data】\n");
    fseek(fp0, 0, SEEK_SET);
    for(i = 0; i <= num; i++){
        fgets(buf, 80, fp0);
        printf("<row %d>: %s", i+1, buf);
    }
    printf("\n\n");
    */
    fclose(fp0);
    gtk_widget_destroy(add_win);
}

void on_cancel_clicked(GtkButton *button, gpointer data)
{
    gtk_widget_destroy(add_win);
}

void selection_made( GtkWidget *clist,
                        gint row,
                        gint column,
                        GdkEventButton *event,
                        gpointer data)
{
    gchar *text;
    gtk_clist_get_text(GTK_CLIST(clist), row, column, &text);
    select_row = row;
    if(select_row >= 0 && select_row < row_count)
        select_flag = TRUE;
    else
        select_flag = FALSE;
}

void combo1_selected(GtkWidget *widget, gpointer data)
{ 
    gchar *text;
    text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget));
    strcpy(protocol, text);
    free(text);
}

void combo2_selected(GtkWidget *widget, gpointer data)
{ 
    gchar *text;
    text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget));
    strcpy(tvalid, text);
    free(text);
}

void combo3_selected(GtkWidget *widget, gpointer data)
{ 
    gchar *text;
    text = gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget));
    strcpy(action, text);
    free(text);
}
