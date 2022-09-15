﻿#pragma checksum "..\..\Decoder.xaml" "{8829d00f-11b8-4213-878b-770e8597ac16}" "BBD243469F8EE381219E65D7BA9A418BAEF20D2E778BC59B5FFF28F4C0DEFB50"
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

using Confuser;
using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Ink;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;


namespace Confuser {
    
    
    /// <summary>
    /// Decoder
    /// </summary>
    public partial class Decoder : System.Windows.Window, System.Windows.Markup.IComponentConnector {
        
        
        #line 8 "..\..\Decoder.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Border Chrome;
        
        #line default
        #line hidden
        
        
        #line 18 "..\..\Decoder.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Grid Root;
        
        #line default
        #line hidden
        
        
        #line 32 "..\..\Decoder.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Label Bar;
        
        #line default
        #line hidden
        
        
        #line 49 "..\..\Decoder.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox path;
        
        #line default
        #line hidden
        
        
        #line 52 "..\..\Decoder.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox input;
        
        #line default
        #line hidden
        
        
        #line 55 "..\..\Decoder.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox output;
        
        #line default
        #line hidden
        
        private bool _contentLoaded;
        
        /// <summary>
        /// InitializeComponent
        /// </summary>
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        public void InitializeComponent() {
            if (_contentLoaded) {
                return;
            }
            _contentLoaded = true;
            System.Uri resourceLocater = new System.Uri("/Confuser;component/decoder.xaml", System.UriKind.Relative);
            
            #line 1 "..\..\Decoder.xaml"
            System.Windows.Application.LoadComponent(this, resourceLocater);
            
            #line default
            #line hidden
        }
        
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "4.0.0.0")]
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Never)]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Design", "CA1033:InterfaceMethodsShouldBeCallableByChildTypes")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        void System.Windows.Markup.IComponentConnector.Connect(int connectionId, object target) {
            switch (connectionId)
            {
            case 1:
            this.Chrome = ((System.Windows.Controls.Border)(target));
            return;
            case 2:
            this.Root = ((System.Windows.Controls.Grid)(target));
            return;
            case 3:
            this.Bar = ((System.Windows.Controls.Label)(target));
            
            #line 32 "..\..\Decoder.xaml"
            this.Bar.MouseDown += new System.Windows.Input.MouseButtonEventHandler(this.Bar_MouseDown);
            
            #line default
            #line hidden
            
            #line 32 "..\..\Decoder.xaml"
            this.Bar.MouseDoubleClick += new System.Windows.Input.MouseButtonEventHandler(this.Bar_MouseDoubleClick);
            
            #line default
            #line hidden
            return;
            case 4:
            
            #line 34 "..\..\Decoder.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.Close_Click);
            
            #line default
            #line hidden
            return;
            case 5:
            this.path = ((System.Windows.Controls.TextBox)(target));
            
            #line 50 "..\..\Decoder.xaml"
            this.path.PreviewDragOver += new System.Windows.DragEventHandler(this.path_PreviewDragOver);
            
            #line default
            #line hidden
            
            #line 50 "..\..\Decoder.xaml"
            this.path.Drop += new System.Windows.DragEventHandler(this.path_Drop);
            
            #line default
            #line hidden
            return;
            case 6:
            
            #line 51 "..\..\Decoder.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.Browse_Click);
            
            #line default
            #line hidden
            return;
            case 7:
            this.input = ((System.Windows.Controls.TextBox)(target));
            
            #line 53 "..\..\Decoder.xaml"
            this.input.MouseEnter += new System.Windows.Input.MouseEventHandler(this.Box_MouseEnter);
            
            #line default
            #line hidden
            return;
            case 8:
            
            #line 54 "..\..\Decoder.xaml"
            ((System.Windows.Controls.Button)(target)).Click += new System.Windows.RoutedEventHandler(this.Translate_Click);
            
            #line default
            #line hidden
            return;
            case 9:
            this.output = ((System.Windows.Controls.TextBox)(target));
            
            #line 56 "..\..\Decoder.xaml"
            this.output.MouseEnter += new System.Windows.Input.MouseEventHandler(this.Box_MouseEnter);
            
            #line default
            #line hidden
            return;
            }
            this._contentLoaded = true;
        }
    }
}

